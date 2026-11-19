# SPDX-FileCopyrightText: 2026 Jason Pena <jpalex@nmsu.edu>
# SPDX-FileCopyrightText: 2026 The Arizona Board of Regents
#
# SPDX-License-Identifier: BSD-2-Clause

"""Safety policies and their verification against a recovered state graph.

A safety policy is written as a subclass of one of the rule base classes:

* :class:`IllegalNodeBaseRule`: no single state may be unsafe.
* :class:`IllegalTransitionBaseRule`: no transition may be unsafe.
* :class:`MinDelayBaseRule`: getting from one kind of state to another must take *at least* some time.
* :class:`MaxDelayBaseRule`: getting from one kind of state to another must take *at most* some time.

:class:`RuleVerifier` then checks the rule against a state graph.

State graph nodes are abstract states, i.e. tuples of ``(field name, value)`` pairs as returned by
:meth:`taveren.AbstractStateFields.generate_abstract_state`, so ``dict(node)`` gives the field values.
Edges may carry a ``time_delta`` attribute, the number of seconds the transition takes.

Examples:
    The examples in this module share this small state graph of a filling station. In the
    examples of individual classes and methods, ``graph``, ``idle``, ``fill`` and ``move``
    refer to it.

    >>> import networkx
    >>> idle = (("MOTOR", 0), ("VALVE", 0))
    >>> fill = (("MOTOR", 0), ("VALVE", 1))
    >>> move = (("MOTOR", 1), ("VALVE", 0))
    >>> graph = networkx.DiGraph()
    >>> graph.add_edge(idle, fill, time_delta=None)
    >>> graph.add_edge(fill, move, time_delta=10)
    >>> graph.add_edge(move, idle, time_delta=5)

    Verify that the motor and the valve are never on together:

    >>> class NoBothOn(IllegalNodeBaseRule):
    ...     def verify_node(self, graph, node):
    ...         return not (dict(node)["MOTOR"] == 1 and dict(node)["VALVE"] == 1)
    >>> safe, src, dst = RuleVerifier(graph).verify(NoBothOn())
    >>> safe
    True
"""

from typing import Generator, Any, Iterable, Tuple, List
import logging

import networkx

from .apis import CauseBase, InstrOpcodeCause

_l = logging.getLogger(name=__name__)


class BaseRule:
    """
    The base class of all safety policies.

    Subclass one of the more specific base classes in this module rather than this one, unless the policy fits none
    of them. A direct subclass must implement :meth:`eval`.

    Examples:
        A rule that requires the graph to have at most three states:

        >>> class AtMostThreeStates(BaseRule):
        ...     def eval(self, graph):
        ...         return graph.number_of_nodes() <= 3, None, None
        >>> AtMostThreeStates().eval(graph)
        (True, None, None)
    """

    def eval(self, graph: "networkx.DiGraph") -> Tuple[bool, Any, Any]:
        """
        Check the rule against ``graph``.

        Args:
            graph: The state graph.

        Returns:
            A ``(safe, src, dst)`` triple. ``safe`` tells whether the rule holds. When it does not, ``src`` is the
            offending node and ``dst``, if not ``None``, is the node at the end of the offending path.

        Raises:
            NotImplementedError: Always, unless overridden.
        """
        raise NotImplementedError()

    def filter_root_causes(self, causes: List[CauseBase]) -> List[CauseBase]:
        """
        Drop root causes that are irrelevant to this rule.

        The default implementation keeps every cause.

        Args:
            causes: Candidate root causes of a violation.

        Returns:
            The causes worth reporting.

        Examples:
            >>> from taveren.apis import InstrOperandCause
            >>> BaseRule().filter_root_causes([InstrOperandCause(0x401000, 1, 15)])
            [<InstrOperandCause 0x401000 operand 1:15>]
        """
        return causes


class IllegalNodeBaseRule(BaseRule):
    """
    Ensure all nodes comply with the defined requirements.

    Subclasses implement :meth:`verify_node`, which is called on every node until one fails.

    Examples:
        >>> class ValveNeverOn(IllegalNodeBaseRule):
        ...     def verify_node(self, graph, node):
        ...         return dict(node)["VALVE"] == 0
        >>> safe, bad_node, _ = ValveNeverOn().eval(graph)
        >>> safe, dict(bad_node)
        (False, {'MOTOR': 0, 'VALVE': 1})
    """

    def verify_node(self, graph: "networkx.DiGraph", node: Any) -> bool:
        """
        Tell whether ``node`` is safe.

        Args:
            graph: The state graph.
            node: The node to check.

        Returns:
            ``True`` if ``node`` complies with the rule.

        Raises:
            NotImplementedError: Always, unless overridden.
        """
        raise NotImplementedError()

    def eval(self, graph: "networkx.DiGraph") -> Tuple[bool, Any, Any]:
        """
        Run :meth:`verify_node` on every node.

        Returns:
            ``(True, None, None)`` if every node is safe, otherwise ``(False, node, None)`` for the first unsafe node.
        """
        for node in graph.nodes():
            r = self.verify_node(graph, node)
            if not r:
                return False, node, None
        return True, None, None


# illegal transition
class IllegalTransitionBaseRule(BaseRule):
    """
    Ensure transitions comply with defined requirements.

    Subclasses implement :meth:`verify_node`, which checks the transitions out of one node.

    Examples:
        The motor must never start right after the valve was open:

        >>> class NoFillThenMove(IllegalTransitionBaseRule):
        ...     def verify_node(self, graph, node):
        ...         if dict(node)["VALVE"] == 1:
        ...             for succ in graph.successors(node):
        ...                 if dict(succ)["MOTOR"] == 1:
        ...                     return False, succ
        ...         return True, None
        >>> safe, src, dst = NoFillThenMove().eval(graph)
        >>> safe, dict(src), dict(dst)
        (False, {'MOTOR': 0, 'VALVE': 1}, {'MOTOR': 1, 'VALVE': 0})
    """

    def verify_node(self, graph: "networkx.DiGraph", node: Any) -> Tuple[bool, Any]:
        """
        Check the transitions out of ``node``.

        Args:
            graph: The state graph.
            node: The source node of the transitions to check.

        Returns:
            ``(True, None)`` if every transition is safe, otherwise ``(False, dst)`` where ``dst`` is the destination
            of an unsafe transition.

        Raises:
            NotImplementedError: Always, unless overridden.
        """
        raise NotImplementedError()

    def eval(self, graph: "networkx.DiGraph") -> Tuple[bool, Any, Any]:
        """
        Run :meth:`verify_node` on every node.

        Returns:
            ``(True, None, None)`` if every transition is safe, otherwise ``(False, src, dst)`` for the first unsafe
            transition.
        """
        for node in graph.nodes():
            safe, dst = self.verify_node(graph, node)
            if not safe:
                return False, node, dst
        return True, None, None


# time as duration
class MinDelayBaseRule(BaseRule):
    """
    Ensure the delay between two states must be at least certain amount of time.

    Subclasses implement :meth:`node_a`, which yields the start states, and :meth:`node_b`, which yields the end
    states for a given start state. The rule fails if any simple path from a start state to one of its end states
    takes less than ``min_delay`` seconds, adding up the ``time_delta`` of its edges (missing or ``None`` counts as
    ``0``).

    Root causes of type :class:`taveren.apis.InstrOpcodeCause` are dropped by :meth:`filter_root_causes`, as timing
    violations come from constants rather than operators.

    Args:
        min_delay: The minimum delay, in seconds.

    Examples:
        The valve must stay open for at least 15 seconds once opened:

        >>> class ValveMin15s(MinDelayBaseRule):
        ...     def node_a(self, graph):
        ...         return [n for n in graph if dict(n)["VALVE"] == 1]
        ...     def node_b(self, graph, start):
        ...         return [n for n in graph.successors(start) if dict(n)["VALVE"] == 0]
        >>> safe, src, dst = ValveMin15s(15).eval(graph)
        MinDelayBaseRule violated: 10 < 15
        >>> safe
        False
    """

    def __init__(self, min_delay):
        self.min_delay = min_delay

    def node_a(self, graph: "networkx.DiGraph") -> Iterable[Any]:
        """
        Yield the states where the measured interval starts.

        Raises:
            NotImplementedError: Always, unless overridden.
        """
        raise NotImplementedError()

    def node_b(self, graph: "networkx.DiGraph", start: tuple) -> Iterable[Any]:
        """
        Yield the states where the interval that began at ``start`` ends.

        Raises:
            NotImplementedError: Always, unless overridden.
        """
        raise NotImplementedError()

    def delay(
        self, graph: "networkx.DiGraph", node_a, node_b
    ) -> Generator[float, None, None]:
        """
        Yield the total delay of every simple path from ``node_a`` to ``node_b``.

        Examples:
            >>> list(MinDelayBaseRule(0).delay(graph, idle, move))
            [10]
        """
        for path in networkx.all_simple_paths(graph, node_a, node_b):
            t = 0
            for src, dst in zip(path, path[1:]):
                data = graph.get_edge_data(src, dst)
                if "time_delta" in data and data["time_delta"] is not None:
                    t += data["time_delta"]
            yield t

    def eval(self, graph) -> Tuple[bool, Any, Any]:
        """
        Check every path between :meth:`node_a` and :meth:`node_b` states.

        Prints a message when the rule is violated.

        Returns:
            ``(True, None, None)`` if every path takes at least ``min_delay``, otherwise ``(False, a, b)`` for the
            first pair of states joined by a path that is too short.
        """
        nodes_a = self.node_a(graph)
        for a in nodes_a:
            nodes_b = self.node_b(graph, a)
            for b in nodes_b:
                for t in self.delay(graph, a, b):
                    if t < self.min_delay:
                        print(f"MinDelayBaseRule violated: {t} < {self.min_delay}")
                        return False, a, b

        return True, None, None

    def filter_root_causes(self, causes: List[CauseBase]) -> List[CauseBase]:
        """
        Drop :class:`taveren.apis.InstrOpcodeCause` causes.

        Examples:
            >>> from taveren.apis import InstrOpcodeCause, InstrOperandCause
            >>> MinDelayBaseRule(15).filter_root_causes([
            ...     InstrOpcodeCause(0x401000, "cmp"),
            ...     InstrOperandCause(0x401000, 1, 10),
            ... ])
            [<InstrOperandCause 0x401000 operand 1:10>]
        """
        # we really do not care about InstrOpcodeCause...
        return [cause for cause in causes if not isinstance(cause, InstrOpcodeCause)]


# time is duration
class MaxDelayBaseRule(BaseRule):
    """
    Ensure the delay between two states cannot exceed certain amount of time.

    The counterpart of :class:`MinDelayBaseRule`: the rule fails if any simple path from a :meth:`node_a` state to
    one of its :meth:`node_b` states takes more than ``max_delay`` seconds.

    Args:
        max_delay: The maximum delay, in seconds.

    Examples:
        The motor must not run for more than 3 seconds:

        >>> class MotorMax3s(MaxDelayBaseRule):
        ...     def node_a(self, graph):
        ...         return [n for n in graph if dict(n)["MOTOR"] == 1]
        ...     def node_b(self, graph, start):
        ...         return [n for n in graph.successors(start) if dict(n)["MOTOR"] == 0]
        >>> safe, src, dst = MotorMax3s(3).eval(graph)
        MaxDelayBaseRule violated: 5 > 3
        >>> safe, dict(src), dict(dst)
        (False, {'MOTOR': 1, 'VALVE': 0}, {'MOTOR': 0, 'VALVE': 0})
    """

    def __init__(self, max_delay):
        self.max_delay = max_delay

    def node_a(self, graph: "networkx.DiGraph") -> Iterable[Any]:
        """
        Yield the states where the measured interval starts.

        Raises:
            NotImplementedError: Always, unless overridden.
        """
        raise NotImplementedError()

    def node_b(self, graph: "networkx.DiGraph", start: tuple) -> Iterable[Any]:
        """
        Yield the states where the interval that began at ``start`` ends.

        Raises:
            NotImplementedError: Always, unless overridden.
        """
        raise NotImplementedError()

    def delay(
        self, graph: "networkx.DiGraph", node_a, node_b
    ) -> Generator[float, None, None]:
        """
        Yield the total delay of every simple path from ``node_a`` to ``node_b``.

        Examples:
            >>> list(MaxDelayBaseRule(0).delay(graph, fill, idle))
            [15]
        """
        for path in networkx.all_simple_paths(graph, node_a, node_b):
            t = 0
            for src, dst in zip(path, path[1:]):
                # print(path)
                data = graph.get_edge_data(src, dst)
                if "time_delta" in data and data["time_delta"] is not None:
                    t += data["time_delta"]
            yield t

    def eval(self, graph) -> Tuple[bool, Any, Any]:
        """
        Check every path between :meth:`node_a` and :meth:`node_b` states.

        Prints a message when the rule is violated.

        Returns:
            ``(True, None, None)`` if no path takes longer than ``max_delay``, otherwise ``(False, a, b)`` for the
            first pair of states joined by a path that is too long.
        """
        nodes_a = self.node_a(graph)
        for a in nodes_a:
            nodes_b = self.node_b(graph, a)
            for b in nodes_b:
                for t in self.delay(graph, a, b):
                    if t > self.max_delay:
                        print(f"MaxDelayBaseRule violated: {t} > {self.max_delay}")
                        return False, a, b

        return True, None, None


class RuleVerifier:
    """
    Finding rule violations by traversing a state graph.

    Args:
        abs_state_graph: The recovered state graph. Its first node is taken as the initial state.

    Examples:
        >>> verifier = RuleVerifier(graph)
        >>> class ValveNeverOn(IllegalNodeBaseRule):
        ...     def verify_node(self, graph, node):
        ...         return dict(node)["VALVE"] == 0
        >>> safe, src, dst = verifier.verify(ValveNeverOn())
        (('MOTOR', 0), ('VALVE', 0))
        <BLANKLINE>
         -> Condition: {'time_delta': None}
        <BLANKLINE>
         -> (('MOTOR', 0), ('VALVE', 1))
        >>> safe
        False
    """

    def __init__(self, abs_state_graph: "networkx.DiGraph"):
        self.abs_state_graph = abs_state_graph

    def verify(self, rule: BaseRule):
        """
        Check ``rule`` against the state graph and print a counterexample if it fails.

        The counterexample is the shortest path from the initial state to the offending state, followed by the path
        to the end state of the violation (if any). Each step prints the edge data, which holds the transition
        conditions and time delta.

        Args:
            rule: The safety policy to check.

        Returns:
            The ``(safe, src, dst)`` triple returned by ``rule.eval``.
        """
        safe, src_node, dst_node = rule.eval(self.abs_state_graph)

        _l.warning("Checked against %s: %s, %s, %s", rule, safe, src_node, dst_node)

        if not safe:
            start_node = list(self.abs_state_graph.nodes())[0]
            print(start_node)
            path_a = networkx.shortest_path(self.abs_state_graph, start_node, src_node)
            for a, b in zip(path_a, path_a[1:]):
                data = self.abs_state_graph.get_edge_data(a, b)
                print(f"\n -> Condition: {data} \n\n -> {b}")
            if dst_node is not None:
                path_b = networkx.shortest_path(
                    self.abs_state_graph, src_node, dst_node
                )
                for a, b in zip(path_b, path_b[1:]):
                    data = self.abs_state_graph.get_edge_data(a, b)
                    print(f"\n -- Condition: {data} \n\n -> {b}")

        return safe, src_node, dst_node
