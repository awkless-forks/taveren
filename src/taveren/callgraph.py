from __future__ import annotations

import re

import networkx
import angr


def call_tree_from_call_graph(
    call_graph: networkx.DiGraph,
) -> dict[int, networkx.DiGraph]:
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
