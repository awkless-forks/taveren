# SPDX-FileCopyrightText: 2026 Jason Pena <jpalex@nmsu.edu>
# SPDX-License-Identifier: MIT

"""Shared names for the doctests in ``src/taveren``.

Run the API examples with ``pytest --doctest-modules src/taveren``. Docstrings that say they
use a shared example (e.g. the state graph in :mod:`taveren.rule_verifier`) get it from here.
"""

import networkx
import pytest


@pytest.fixture(autouse=True)
def _taveren_doctest_namespace(doctest_namespace):
    # The filling-station state graph from the taveren.rule_verifier module docs.
    idle = (("MOTOR", 0), ("VALVE", 0))
    fill = (("MOTOR", 0), ("VALVE", 1))
    move = (("MOTOR", 1), ("VALVE", 0))
    graph = networkx.DiGraph()
    graph.add_edge(idle, fill, time_delta=None)
    graph.add_edge(fill, move, time_delta=10)
    graph.add_edge(move, idle, time_delta=5)
    doctest_namespace.update(idle=idle, fill=fill, move=move, graph=graph)
