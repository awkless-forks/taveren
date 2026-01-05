from __future__ import annotations
from functools import wraps
from collections import defaultdict

import sys
import re

import networkx
import angr
from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeWalker


FAIL_FAST = False


#
# Utility functions
#

def cache_this(cache_dict: dict):
    def decorator(func):
        @wraps(func)
        def wrapper(proj, func_addr, *args, **kwargs):
            if func_addr in cache_dict:
                return cache_dict[func_addr]
            r = func(proj, func_addr, *args, **kwargs)
            cache_dict[func_addr] = r
            return r
        return wrapper
    return decorator


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

#
# Decompiled function traversal
#

class FunctionCallWithinALoopFinder(CStructuredCodeWalker):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.in_loop: bool = False
        self.func_addrs_in_loop: set[int] = set()

    def handle_CWhileLoop(self, obj):
        in_loop = self.in_loop
        self.in_loop = True

        obj = super().handle_CWhileLoop(obj)

        self.in_loop = in_loop
        return obj

    def handle_CDoWhileLoop(self, obj):
        in_loop = self.in_loop
        self.in_loop = True

        obj = super().handle_CDoWhileLoop(obj)

        self.in_loop = in_loop
        return obj

    def handle_CFunctionCall(self, obj):
        if self.in_loop and obj.callee_func is not None:
            self.func_addrs_in_loop.add(obj.callee_func.addr)
        return super().handle_CFunctionCall(obj)


#
# Cache
#

CACHE_WHILE_LOOP: dict[int, bool] = {}
CACHE_STATE_TRANS: dict[int, bool] = {}

#
# Logic
#

@cache_this(CACHE_WHILE_LOOP)
def has_while_loop(proj: angr.Project, func_addr: int, funcs_within_loop: list[int]) -> bool:
    func = proj.kb.functions.get_by_addr(func_addr)
    if func is None:
        return False

    if func.is_simprocedure or func.is_syscall or func.is_plt or func.is_alignment:
        return False

    # is there a loop in the function graph?
    g = func.graph
    if networkx.is_directed_acyclic_graph(g):
        return False

    print(f"[.] has_while_loop: Decompiling function {func.name}@{func.addr:#x}...")
    dec = proj.analyses.Decompiler(func, fail_fast=FAIL_FAST)
    if dec.codegen is None or dec.codegen.text is None:
        print(f"Decompiler failed for function {func.name}@{func.addr:#x}")
        return False
    if not "while (" in dec.codegen.text:
        return False

    # which functions are called within the loop?
    finder = FunctionCallWithinALoopFinder()
    finder.handle(dec.codegen.cfunc)
    funcs_within_loop.extend(sorted(finder.func_addrs_in_loop))

    return True


@cache_this(CACHE_STATE_TRANS)
def likely_state_transition_function(proj: angr.Project, func_addr: int) -> bool:
    func = proj.kb.functions.get_by_addr(func_addr)
    if func is None:
        return False

    if func.is_simprocedure or func.is_syscall or func.is_plt or func.is_alignment:
        return False

    print(f"[.] likely_state_transition_function: Decompiling function {func.name}@{func.addr:#x}...")
    dec = proj.analyses.Decompiler(func, fail_fast=FAIL_FAST)
    if dec.codegen is None or dec.codegen.text is None:
        print(f"Decompiler failed for function {func.name}@{func.addr:#x}")
        return False

    # case 1: has a large switch-case construct
    if "switch (" in dec.codegen.text and dec.codegen.text.count("case ") >= 5:
        return True

    # case 2: has many cascading if-else statements
    if dec.codegen.text.count("if (") >= 8:
        return True

    return False


def count_ifs(proj: angr.Project, func_addr: int) -> int:
    func = proj.kb.functions.get_by_addr(func_addr)
    if func is None:
        return 0

    if func.is_simprocedure or func.is_syscall or func.is_plt or func.is_alignment:
        return 0

    print(f"[.] count_ifs: Decompiling function {func.name}@{func.addr:#x}...")
    dec = proj.analyses.Decompiler(func, fail_fast=FAIL_FAST)
    if dec.codegen is None or dec.codegen.text is None:
        print(f"Decompiler failed for function {func.name}@{func.addr:#x}")
        return 0

    return dec.codegen.text.count("if (")


def analyze(binary_path: str) -> None:
    print(f"Analyzing binary for cycle detection: {binary_path}")

    proj = angr.Project(binary_path, auto_load_libs=False)

    # CFG recovery
    cfg = proj.analyses.CFGFast(force_smart_scan=False, normalize=True, show_progressbar=True)
    proj.analyses.CompleteCallingConventions(show_progressbar=True)

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

    # build a call tree
    call_trees = call_tree_from_call_graph(cfg.functions.callgraph)

    # traverse each call tree
    candidates = []
    # func_addr_0 -> (func_addr_1 -> (if_count, -depth))
    ifs: dict[int, dict[int, tuple[int, int]]] = defaultdict(dict)
    for func_start_addr, call_tree in call_trees.items():
        # along each call tree, look for cases where a node contains a while(cond) loop and one of its descendants
        # is a state-transition function
        if len(call_tree) < 2:
            continue

        for func_addr_0 in networkx.bfs_tree(call_tree, func_start_addr):
            funcs_within_loop: list[int] = []
            if has_while_loop(proj, func_addr_0, funcs_within_loop) and funcs_within_loop:
                has_a_candidate = False
                for func_within_loop in funcs_within_loop:
                    traversed = set()
                    queue = [(0, func_within_loop)]
                    while queue:
                        depth, func_addr_1 = queue.pop(0)
                        if func_addr_1 in traversed:
                            continue
                        traversed.add(func_addr_1)

                        if likely_state_transition_function(proj, func_addr_1):
                            func_name_0 = proj.kb.functions[func_addr_0].name
                            func_name_1 = proj.kb.functions[func_addr_1].name
                            print(
                                f"Potential cycle detection pattern found: "
                                f"Function {func_name_0} contains a while(cond) loop, "
                                f"and its descendant function {func_name_1} is a likely state-transition function."
                            )
                            candidates.append((func_addr_0, func_addr_1))
                            has_a_candidate = True
                        else:
                            if not has_a_candidate:
                                ifs[func_addr_0][func_addr_1] = count_ifs(proj, func_addr_1), -depth
                            for succ in call_tree.successors(func_addr_1):
                                if succ not in traversed:
                                    queue.append((depth + 1, succ))

    if candidates:
        print(f"Found {len(candidates)} candidate function pairs.")
        for func_addr_0, func_addr_1 in candidates:
            func_name_0 = proj.kb.functions[func_addr_0].name
            func_name_1 = proj.kb.functions[func_addr_1].name
            print(f"- {func_name_0}@{func_addr_0:#x} -> {func_name_1}@{func_addr_1:#x}")
    else:
        # resort to if count
        for func_addr_0, d in ifs.items():
            if not d:
                continue
            func_name_0 = proj.kb.functions[func_addr_0].name
            func_addr_1 = max(d, key=d.get)
            if d[func_addr_1][0] <= 3:
                # contains at least three ifs
                continue
            func_name_1 = proj.kb.functions[func_addr_1].name
            print(
                f"Potential cycle detection pattern found (by if-count heuristic): "
                f"- {func_name_0}@{func_addr_0:#x} -> {func_name_1}@{func_addr_1:#x}"
            )


def main():
    binary_path = sys.argv[1]
    analyze(binary_path)


if __name__ == "__main__":
    import sys
    sys.setrecursionlimit(5000)
    main()
