from __future__ import annotations

from collections import defaultdict
import argparse
import sys
import re

import networkx

import angr
from angr.ailment.statement import Store
from angr.ailment.expression import Const, BinaryOp, VirtualVariable

THRESHOLD = 10


def call_tree_from_call_graph(call_graph: networkx.DiGraph) -> dict[int, networkx.DiGraph]:
    call_trees = {}
    entry_nodes = [n for n, d in call_graph.in_degree() if d == 0]

    def dfs(node, call_tree):
        call_tree.add_node(node)
        for succ in call_graph.successors(node):
            if succ in call_tree:
                continue
            call_tree.add_edge(node, succ)
            dfs(succ, call_tree)

    for entry in entry_nodes:
        call_tree = networkx.DiGraph()
        call_trees[entry] = call_tree
        dfs(entry, call_tree)
        assert networkx.is_tree(call_tree)

    return call_trees


def get_global_writes(proj: angr.Project, func: angr.knowledge_plugins.Function) -> list:
    # again, we decompile these functions to find global writes!
    # we really don't have to, but this is fun

    global_accesses = []

    print(f"[.] Decompiling function {func.name}...")
    dec = proj.analyses.Decompiler(func)
    print(f"[+] Decompiled!")
    for block in dec.clinic.cc_graph:
        for stmt in block.statements:
            if isinstance(stmt, Store):
                if isinstance(stmt.addr, Const):
                    write_addr = stmt.addr.value_int
                    write_size = stmt.size
                    write_data = stmt.data
                    global_accesses.append((write_addr, write_size, write_data))
                elif isinstance(stmt.addr, BinaryOp) and stmt.addr.op == "Add":
                    if isinstance(stmt.addr.operands[0], VirtualVariable) and isinstance(stmt.addr.operands[1], Const):
                        var = stmt.addr.operands[0]
                        offset = stmt.addr.operands[1].value_int
                        write_addr = offset
                        write_size = stmt.size
                        write_data = stmt.data
                        global_accesses.append((write_addr, write_size, write_data))

    return global_accesses


def get_init_function_candidates(proj: angr.Project, scan_cycle_func_addr: int, entry_point: int, only_reachable_from_ep: bool) -> list[tuple[int, int, bool]]:
    # build a call tree and then report functions that write to global data sections

    call_trees = call_tree_from_call_graph(proj.kb.functions.callgraph)

    # - any functions that are below the scan cycle function are not init functions
    # - any functions that do not write to global data sections are not init functions

    # bfs
    init_func_candidate_graph = networkx.DiGraph()
    blacklist = set()
    reachable_from_entry_point = set()
    for root, g in call_trees.items():
        if scan_cycle_func_addr in g:
            # anything along the predecessor path to scan_cycle_func_addr is not a viable init function
            queue = [scan_cycle_func_addr]
            while queue:
                func_addr = queue.pop(0)
                blacklist.add(func_addr)
                for pred in g.predecessors(func_addr):
                    queue.append(pred)

        if entry_point in g:
            reachable_from_entry_point |= set(g)

        if only_reachable_from_ep and root not in reachable_from_entry_point:
            continue

        queue = [root]
        while queue:
            func_addr = queue.pop(0)
            if func_addr == scan_cycle_func_addr:
                continue
            for succ in g.successors(func_addr):
                queue.append(succ)
                init_func_candidate_graph.add_edge(func_addr, succ)

    global_writes: defaultdict[int, int] = defaultdict(int)
    for candidate_addr in init_func_candidate_graph:
        if candidate_addr in blacklist:
            continue
        func = proj.kb.functions[candidate_addr]
        if func.is_plt or func.is_alignment or func.is_simprocedure:
            continue
        global_data_accesses = get_global_writes(proj, func)
        global_writes[func.addr] = len(global_data_accesses)

    # patch in the total number of global writes along each subtree to the root of the subtree
    accumulated_write_counts: dict[int, int] = {}
    for root, g in call_trees.items():
        if only_reachable_from_ep and root not in reachable_from_entry_point:
            continue

        for node in networkx.dfs_postorder_nodes(g, root):
            if node in blacklist:
                continue
            succ_write_count = sum(global_writes.get(succ, 0) for succ in g.successors(node))
            accumulated_write_counts[node] = global_writes.get(node, 0) + succ_write_count

    candidates = []
    for func_addr, count in accumulated_write_counts.items():
        func = proj.kb.functions[func_addr]
        if func.is_plt:
            continue
        if count >= THRESHOLD:
            candidates.append((func_addr, count, func_addr in reachable_from_entry_point))

    return candidates



def find_init(bin_path: str, scan_cycle_func_addr: int | str, entry_point: str | int, only_reachable_from_ep: bool = False):
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFG(normalize=True, show_progressbar=True)

    # HACK: Freaking PPC uses r30 weirdly for binary- and glibc GOT; we gotta patch the callgraph properly
    if proj.arch.name == "PPC32":
        print("[.] Patching callgraph for PPC32 GOT calls...")
        for func in proj.kb.functions.values():
            m = re.search(r"\.got2\.plt_pic32\.([^@]+)$", func.name)
            if m is not None:
                target_func_name = m.group(1)
                try:
                    target_func = proj.kb.functions[target_func_name]
                except KeyError:
                    continue
                cfg.functions.callgraph.add_edge(func.addr, target_func.addr)

    proj.analyses.CompleteCallingConventions(show_progressbar=True)

    try:
        entry_func = proj.kb.functions["startPLC"]  # may not exist in every binary :)
    except KeyError:
        try:
            entry_func = proj.kb.functions["main"]
        except KeyError:
            raise("Entry function is not 'startPLC' or 'main' in the binary!")

    # special case: angr is too smart and creates a fake CFG edge between SimProcedure pthread_create and the actual
    # thread routine. we gotta redo it
    try:
        pthread_create_func = proj.kb.functions["pthread_create"]
        for succ_addr in list(cfg.kb.functions.callgraph.successors(pthread_create_func.addr)):
            cfg.kb.functions.callgraph.remove_edge(pthread_create_func.addr, succ_addr)
    except KeyError:
        pass

    scan_cycle_function = cfg.kb.functions[scan_cycle_func_addr]
    init_func_candidates = get_init_function_candidates(proj, scan_cycle_function.addr, entry_func.addr, only_reachable_from_ep)
    init_func_candidates = sorted(init_func_candidates, key=lambda x: (x[2], x[1]), reverse=True)

    for func_addr, write_count, reachable_from_ep in init_func_candidates:
        func = proj.kb.functions[func_addr]
        reachable = "Reachable from EP" if reachable_from_ep else "Not reachable from EP"
        print(f"{reachable}: Function {func.name} writes to {write_count} global locations")


def main():
    config = {
        "tl_original": {
            "path": "../artifacts/Traffic_Light_original/build/Traffic_Light_original.so",
            "scan_cycle_func_addr": 0x405719,
            "entry_point": "startPLC",
            "only_reachable_from_ep": True,
        },
        "tl.5": {
            "path": "../artifacts/Traffic_Light_Short_Ped_5/build/Traffic_Light_Short_Ped.so",
            "scan_cycle_func_addr": 0x40D640,
            "entry_point": "startPLC",
            "only_reachable_from_ep": True,
        },
        "tl.addsensor": {
            "path": "../artifacts/traffic_light_addsensor_x86-64/Traffic_Light_addsensor_x86-64.so",
            "scan_cycle_func_addr": 0x42C83D,
            "entry_point": "startPLC",
            "only_reachable_from_ep": True,
        },
        "pack.3": {
            "path": "../artifacts/packaging_sfc/build/packaging_sfc_powerpc.so",
            "scan_cycle_func_addr": 0x41689c,
            "entry_point": "startPLC",
            "only_reachable_from_ep": True,
        }
    }

    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Name of the target PLC program to analyze")

    args = parser.parse_args()

    target = config[args.target.lower()]
    find_init(
        target["path"],
        target["scan_cycle_func_addr"],
        target["entry_point"],
        only_reachable_from_ep=target["only_reachable_from_ep"],
    )


if __name__ == "__main__":

    # main()

    binary_path = sys.argv[1]
    scan_cycle_func_input = sys.argv[2]
    if scan_cycle_func_input.startswith("0x"):
        scan_cycle_addr = int(sys.argv[2], 16)
    else:
        scan_cycle_addr = sys.argv[2]
    # entry_function_name = sys.argv[3]
    find_init(binary_path, scan_cycle_addr, "test", True)

