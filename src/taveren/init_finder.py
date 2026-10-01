from __future__ import annotations

from collections import defaultdict
import argparse

import networkx

import angr
from angr.ailment.statement import Store
from angr.ailment.expression import Const, BinaryOp, VirtualVariable

from .callgraph import call_tree_from_call_graph, patch_ppc32_got_calls

THRESHOLD = 10


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

    patch_ppc32_got_calls(proj, cfg.functions.callgraph)

    proj.analyses.CompleteCallingConventions(show_progressbar=True)

    try:
        entry_func = proj.kb.functions["startPLC"]  # may not exist in every binary :)
    except KeyError:
        try:
            entry_func = proj.kb.functions["main"]
        except KeyError:
            raise ValueError("Entry function is not 'startPLC' or 'main' in the binary!")

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


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="taveren-init-finder",
        description="Rank candidate initialization functions of a PLC binary.",
    )
    parser.add_argument("binary", help="path to the PLC binary to analyze")
    parser.add_argument(
        "scan_cycle_func",
        help="scan cycle function, as a hex address (0x...) or a symbol name",
    )
    parser.add_argument(
        "--include-unreachable",
        action="store_true",
        help="also report candidates not reachable from the entry point",
    )
    args = parser.parse_args(argv)

    scan_cycle_func = args.scan_cycle_func
    if scan_cycle_func.startswith("0x"):
        scan_cycle_func = int(scan_cycle_func, 16)

    find_init(args.binary, scan_cycle_func, "test", only_reachable_from_ep=not args.include_unreachable)


if __name__ == "__main__":
    main()
