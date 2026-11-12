"""Detect the scan cycle function of a PLC binary.

A PLC program runs its logic in a *scan cycle*: an endless loop that reads the inputs, runs the
program once and writes the outputs. The function called from that loop, which holds the program's
state machine, is the one Ta'veren recovers an FSM from. :func:`analyze` finds it with decompiler
heuristics; it is also available as the ``taveren-scan-cycle`` command.

Examples:
    >>> from taveren.scan_cycle import analyze
    >>> analyze("tests/fixtures/water_tank/build/water_tank.so")  # doctest: +SKIP
    ...
    Potential cycle detection pattern found (by if-count heuristic): - PLC_thread_proc@0x40395a -> SR_body__@0x41c24a
"""

from __future__ import annotations
from functools import wraps
from collections import defaultdict

import argparse
import sys

import networkx
import angr
from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeWalker

from .callgraph import call_tree_from_call_graph, patch_ppc32_got_calls

FAIL_FAST = False


#
# Utility functions
#


def cache_this(cache_dict: dict):
    """
    Memoize a ``func(proj, func_addr, ...)`` function on ``func_addr``.

    Results are stored in ``cache_dict``, so they are shared by every caller and every project; clear it before
    analyzing another binary. Other arguments are not part of the key.

    Args:
        cache_dict: The dict to store results in.

    Examples:
        >>> cache = {}
        >>> @cache_this(cache)
        ... def decompile(proj, func_addr):
        ...     print(f"decompiling {func_addr:#x}")
        ...     return func_addr * 2
        >>> decompile(None, 0x10)
        decompiling 0x10
        32
        >>> decompile(None, 0x10)
        32
        >>> cache
        {16: 32}
    """

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


#
# Decompiled function traversal
#


class FunctionCallWithinALoopFinder(CStructuredCodeWalker):
    """
    Collect the functions called inside ``while`` and ``do``-``while`` loops of decompiled code.

    Attributes:
        func_addrs_in_loop: Addresses of the functions called inside a loop.

    Examples:
        >>> dec = proj.analyses.Decompiler(proj.kb.functions["PLC_thread_proc"])  # doctest: +SKIP
        >>> finder = FunctionCallWithinALoopFinder()  # doctest: +SKIP
        >>> finder.handle(dec.codegen.cfunc)  # doctest: +SKIP
        >>> [proj.kb.functions[a].name for a in sorted(finder.func_addrs_in_loop)]  # doctest: +SKIP
    """

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
def has_while_loop(
    proj: angr.Project, func_addr: int, funcs_within_loop: list[int]
) -> bool:
    """
    Tell whether a function contains a ``while`` loop, and collect the functions called inside it.

    A scan cycle is driven by a loop such as ``while (running) { read_inputs(); run(); write_outputs(); }``. Only
    functions whose CFG has a cycle are decompiled. Results are cached in ``CACHE_WHILE_LOOP``; on a cache hit
    ``funcs_within_loop`` is not filled again.

    Args:
        proj: The angr project, with functions recovered.
        func_addr: The function to check.
        funcs_within_loop: A list that the addresses of functions called inside a loop are appended to.

    Returns:
        ``True`` if the decompiled function has a ``while`` loop.

    Examples:
        >>> callees = []  # doctest: +SKIP
        >>> has_while_loop(proj, proj.kb.functions["PLC_thread_proc"].addr, callees)  # doctest: +SKIP
        True
    """
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
    """
    Tell whether a function looks like it implements state transitions.

    A function qualifies if its decompiled code has a ``switch`` with at least 5 cases, or at least 8 ``if``
    statements. Results are cached in ``CACHE_STATE_TRANS``.

    Args:
        proj: The angr project, with functions recovered.
        func_addr: The function to check.

    Returns:
        ``True`` if the function is a likely state transition function.

    Examples:
        >>> likely_state_transition_function(proj, 0x41C24A)  # doctest: +SKIP
    """
    func = proj.kb.functions.get_by_addr(func_addr)
    if func is None:
        return False

    if func.is_simprocedure or func.is_syscall or func.is_plt or func.is_alignment:
        return False

    print(
        f"[.] likely_state_transition_function: Decompiling function {func.name}@{func.addr:#x}..."
    )
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
    """
    Count the ``if`` statements in a decompiled function.

    Used as a fallback ranking when no function passes :func:`likely_state_transition_function`.

    Returns:
        The number of ``if`` statements, or ``0`` if the function cannot be decompiled.

    Examples:
        >>> count_ifs(proj, 0x41C24A)  # doctest: +SKIP
    """
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
    """
    Find and print the scan cycle function of a PLC binary.

    Walks each call tree of the binary looking for a function with a ``while`` loop whose callees (direct or
    indirect) include a likely state transition function; each such pair is printed. If there is none, the callee
    with the most ``if`` statements (more than 3) under each looping function is printed instead. The second
    function of a pair is the scan cycle function to pass to :mod:`taveren.init_finder` and
    :mod:`taveren.statevars`.

    This is the ``taveren-scan-cycle`` command.

    Args:
        binary_path: The path of the PLC binary.

    Examples:
        Find the scan cycle of the water tank (output from ``experiments/scan_cycle/outputs``, progress omitted):

        >>> analyze("tests/fixtures/water_tank/build/water_tank.so")  # doctest: +SKIP
        Analyzing binary for cycle detection: tests/fixtures/water_tank/build/water_tank.so
        ...
        Potential cycle detection pattern found (by if-count heuristic): - PLC_thread_proc@0x40395a -> SR_body__@0x41c24a
    """
    print(f"Analyzing binary for cycle detection: {binary_path}")

    proj = angr.Project(binary_path, auto_load_libs=False)

    # CFG recovery
    cfg = proj.analyses.CFGFast(
        force_smart_scan=False, normalize=True, show_progressbar=True
    )
    proj.analyses.CompleteCallingConventions(show_progressbar=True)

    patch_ppc32_got_calls(proj, cfg.functions.callgraph)

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
            if (
                has_while_loop(proj, func_addr_0, funcs_within_loop)
                and funcs_within_loop
            ):
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
                                ifs[func_addr_0][func_addr_1] = (
                                    count_ifs(proj, func_addr_1),
                                    -depth,
                                )
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


def main(argv: list[str] | None = None) -> None:
    """
    Entry point of ``taveren-scan-cycle``.

    Args:
        argv: The command-line arguments, without the program name. Defaults to ``sys.argv[1:]``.

    Examples:
        >>> main(["tests/fixtures/water_tank/build/water_tank.so"])  # doctest: +SKIP

        is the same as running::

            taveren-scan-cycle tests/fixtures/water_tank/build/water_tank.so
    """
    parser = argparse.ArgumentParser(
        prog="taveren-scan-cycle",
        description="Detect the scan cycle function of a PLC binary.",
    )
    parser.add_argument("binary", help="path to the PLC binary to analyze")
    args = parser.parse_args(argv)

    sys.setrecursionlimit(5000)
    analyze(args.binary)


if __name__ == "__main__":
    main()
