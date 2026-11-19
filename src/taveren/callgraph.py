# SPDX-FileCopyrightText: 2026 Jason Pena <jpalex@nmsu.edu>
# SPDX-FileCopyrightText: 2026 The Arizona Board of Regents
#
# SPDX-License-Identifier: BSD-2-Clause

"""Call graph helpers shared by the pre-processing tools.

:mod:`taveren.scan_cycle` and :mod:`taveren.init_finder` walk the call graph of a PLC binary
as a set of trees, one per entry function. This module builds those trees and fixes up call
graphs that angr gets wrong.
"""

from __future__ import annotations

import re

import networkx
import angr


def call_tree_from_call_graph(
    call_graph: networkx.DiGraph,
) -> dict[int, networkx.DiGraph]:
    """
    Split a call graph into one call tree per entry function.

    An entry function is a node with no callers. Each tree is the depth-first spanning tree of the functions
    reachable from its entry, so a function called from several places appears under the first caller visited, and
    recursion back edges are dropped. Functions reachable from several entries appear in several trees.

    Args:
        call_graph: A call graph whose nodes are function addresses, such as
            ``cfg.functions.callgraph``.

    Returns:
        A dict mapping each entry function to its call tree.

    Examples:
        >>> import networkx
        >>> cg = networkx.DiGraph([
        ...     (0x100, 0x200), (0x100, 0x300),
        ...     (0x200, 0x300),               # 0x300 has two callers
        ...     (0x300, 0x200),               # recursion
        ...     (0x400, 0x300),               # a second entry function
        ... ])
        >>> trees = call_tree_from_call_graph(cg)
        >>> sorted(hex(entry) for entry in trees)
        ['0x100', '0x400']
        >>> sorted((hex(u), hex(v)) for u, v in trees[0x100].edges)
        [('0x100', '0x200'), ('0x200', '0x300')]
        >>> sorted(hex(n) for n in trees[0x400])
        ['0x200', '0x300', '0x400']
    """
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


def patch_ppc32_got_calls(proj: angr.Project, call_graph: networkx.DiGraph) -> None:
    """
    Add the call edges that angr misses for PPC32 calls through the GOT.

    PPC32 binaries call through ``.got2.plt_pic32.<name>`` stubs that angr does not resolve. For every such stub, an
    edge from the stub to the function ``<name>`` is added to ``call_graph``. Does nothing for other architectures.

    Args:
        proj: The angr project. Its knowledge base must already hold the functions (run a CFG first).
        call_graph: The call graph to patch in place.

    Examples:
        >>> import angr
        >>> proj = angr.Project("tests/fixtures/packaging_sfc/build/packaging_sfc_powerpc.so",
        ...                     auto_load_libs=False)  # doctest: +SKIP
        >>> cfg = proj.analyses.CFGFast(normalize=True)  # doctest: +SKIP
        >>> patch_ppc32_got_calls(proj, cfg.functions.callgraph)  # doctest: +SKIP
        [.] Patching callgraph for PPC32 GOT calls...
    """
    # HACK: Freaking PPC uses r30 weirdly for binary- and glibc GOT; we gotta patch the callgraph properly
    if proj.arch.name != "PPC32":
        return

    print("[.] Patching callgraph for PPC32 GOT calls...")
    for func in proj.kb.functions.values():
        m = re.search(r"\.got2\.plt_pic32\.([^@]+)$", func.name)
        if m is not None:
            target_func_name = m.group(1)
            try:
                target_func = proj.kb.functions[target_func_name]
            except KeyError:
                continue
            call_graph.add_edge(func.addr, target_func.addr)
