# SPDX-FileCopyrightText: 2026 Jason Pena <jpalex@nmsu.edu>
# SPDX-FileCopyrightText: 2026 The Arizona Board of Regents
#
# SPDX-License-Identifier: BSD-2-Clause

"""Abstract states: the nodes of a recovered state graph.

A PLC program's concrete memory is far too large to use as an FSM state. Ta'veren instead
describes each state by the values of a few memory locations (outputs and state variables),
called *fields*. :class:`AbstractStateFields` says where those fields live in memory, and
:meth:`AbstractStateFields.generate_abstract_state` reads them from an angr state.
"""

from typing import Dict, Tuple, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from angr import SimState


class AbstractState:
    """
    An abstract state in a state graph.

    An abstract state is defined by a set of fields (:class:`AbstractStateFields`) and the value of each field.

    Args:
        fields: The field descriptions this state is defined over.
        values: The value of each field, keyed by field name.

    Examples:
        >>> fields = AbstractStateFields({"VALVE": (0x1000, "bool", 1)})
        >>> s = AbstractState(fields, {"VALVE": 1})
        >>> s.values["VALVE"]
        1
    """

    def __init__(self, fields: "AbstractStateFields", values: Dict[str, Any]):
        self.fields = fields
        self.values = values


class AbstractStateFields:
    """
    Describes where each field of an abstract state is stored.

    Each field maps a name to an ``(address, type, size)`` tuple:

    * ``address``: absolute address of the field in memory. For ``"pin"`` fields, the key of the field in
      ``state.globals`` instead.
    * ``type``: ``"pin"``, ``"double"``, or anything else (read as a raw integer).
    * ``size``: size of the field in bytes.

    These tuples are usually built from an environment model with
    :func:`taveren.env_model.generate_field_desc`.

    Args:
        fields: Field descriptions, keyed by field name.

    Examples:
        >>> fields = AbstractStateFields({
        ...     "CONVEYOR_MOTOR": (0x43B5D8, "bool", 1),
        ...     "PRODUCT_VALVE": (0x43B5F8, "bool", 1),
        ... })
        >>> sorted(fields.fields)
        ['CONVEYOR_MOTOR', 'PRODUCT_VALVE']
    """

    def __init__(self, fields: Dict[str, Tuple[int, str, int]]):
        self.fields = fields

    def generate_abstract_state(self, state: "SimState") -> Tuple[Tuple[str, Any]]:
        """
        Read every field from ``state`` and return the abstract state.

        The result is a tuple of ``(field name, value)`` pairs in field order. It is hashable, so it can be used
        directly as a node in a state graph, and ``dict(result)`` gives a name-to-value mapping.

        A ``"pin"`` field that is missing from ``state.globals`` reads as ``0``.

        Args:
            state: The angr state to read the fields from. Symbolic values are concretized with
                ``state.solver.eval``.

        Returns:
            A tuple of ``(field name, value)`` pairs.

        Examples:
            >>> import angr
            >>> from angr import claripy
            >>> proj = angr.load_shellcode(b"\\xc3", arch="amd64")
            >>> state = proj.factory.blank_state()
            >>> state.memory.store(0x1000, claripy.BVV(1, 8))
            >>> state.memory.store(0x1001, claripy.BVV(0, 8))
            >>> fields = AbstractStateFields({
            ...     "MOTOR": (0x1000, "bool", 1),
            ...     "VALVE": (0x1001, "bool", 1),
            ... })
            >>> fields.generate_abstract_state(state)
            (('MOTOR', 1), ('VALVE', 0))
        """
        lst = []
        for field, (offset, type_, size) in self.fields.items():
            if type_ == "pin":
                try:
                    val = state.solver.eval(state.globals[offset])
                except KeyError:
                    val = 0
            elif type_ == "double":
                val = state.solver.eval(
                    state.memory.load(
                        offset, size=size, endness=state.arch.memory_endness
                    ).raw_to_fp()
                )
            else:
                val = state.solver.eval(state.memory.load(offset, size=size))
            lst.append((field, val))
        return tuple(lst)
