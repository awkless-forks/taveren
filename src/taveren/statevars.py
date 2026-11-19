# SPDX-FileCopyrightText: 2026 Jason Pena <jpalex@nmsu.edu>
# SPDX-FileCopyrightText: 2026 The Arizona Board of Regents
#
# SPDX-License-Identifier: BSD-2-Clause

"""Identify the state variables of a PLC program.

State variables hold the current state of the program's state machine from one scan cycle to the
next. Ta'veren uses them, together with the outputs, to tell abstract states apart; they go in the
environment model with type ``statevar`` (see :mod:`taveren.env_model`).

:func:`analyse_statevars` finds candidates in the decompiled scan cycle; :func:`run_one` wraps it
for the ``taveren-statevars`` command.

Examples:
    >>> from taveren.statevars import run_one
    >>> run_one("tests/fixtures/water_tank/build/water_tank.so", [0x41C24A])  # doctest: +SKIP
    ...
    State variable candidate <Global 0x43a598:1 bytes>,  offset = 0x8
    True
"""

from __future__ import annotations
from enum import Enum
import argparse
import os
import pathlib
import sys

sys.setrecursionlimit(50000)
import traceback
from typing import Any, DefaultDict, Dict, List, Optional, Union
from collections import defaultdict

from angr.ailment import Block
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.statement import ConditionalJump, Statement, Store, Assignment
from angr.ailment.expression import (
    Call,
    Expression,
    Load,
    Const,
    VirtualVariable,
    VirtualVariableCategory,
    Convert,
    BinaryOp,
    Register,
)
import angr
from angr.utils.graph import GraphUtils
from angr.analyses.s_reaching_definitions import SRDAModel
from angr.code_location import ExternalCodeLocation

base_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../../")


class ExprDependsOnExternal(AILBlockViewer):
    """
    Tell whether an AIL expression depends on data from outside the function.

    After walking an expression, ``depends_on_external`` is set if it uses a value defined outside the function
    (a function argument or global memory), and ``depends_on_stack`` if it uses the stack pointer.

    Args:
        nodes_dict: The decompiled function's AIL blocks, keyed by ``(address, index)``.
        srda: The SSA reaching definitions model of the function.
    """

    def __init__(self, nodes_dict: dict[tuple[int, int | None], Block], srda):
        super().__init__()
        self.depends_on_external: bool = False
        self.depends_on_stack: bool = False

        self.nodes_dict = nodes_dict
        self.srda = srda

        self.replace_vvar = []

    def _handle_VirtualVariable(
        self,
        expr_idx: int,
        expr: VirtualVariable,
        stmt_idx: int,
        stmt: Statement,
        block: Block | None,
    ):
        if expr.category == VirtualVariableCategory.STACK:
            self.depends_on_stack = True
        if expr.varid in self.srda.all_vvar_definitions:
            def_loc = self.srda.all_vvar_definitions[expr.varid]
            if isinstance(def_loc, ExternalCodeLocation):
                # it's external!
                self.depends_on_external = True
            else:
                def_stmt = self.nodes_dict[
                    (def_loc.block_addr, def_loc.block_idx)
                ].statements[def_loc.stmt_idx]
                if isinstance(def_stmt, Assignment):
                    src = def_stmt.src
                    if isinstance(src, Convert):
                        src = src.operand
                    if isinstance(src, Load) and isinstance(src.addr, Const):
                        # loading from a global location
                        self.depends_on_external = True
                        self.replace_vvar.append((expr, src))
                        return
                    else:
                        # fixme: hack, need to make the stack variable check recursive
                        self.depends_on_stack = True
                        return


def _expand(
    intermediate_global_vars: dict[int, set[Load]], addr: int, seen: set[Load]
) -> set[Load]:
    # this function may loop forever; fix it after -- Fish
    expanded = set()
    if addr in intermediate_global_vars:
        for expr in intermediate_global_vars[addr]:
            if expr in seen:
                continue
            seen.add(expr)
            next_ = _expand(intermediate_global_vars, expr.addr.value, seen)
            if not next_:
                expanded.add(expr)
            else:
                expanded |= next_
    return expanded


class ConditionWalker(AILBlockViewer):
    """
    Collect the global variables loaded and stored by an AIL expression or statement.

    Loads from global variables that only hold copies of other globals (``intermediate_global_vars``) are expanded
    to the original globals.

    Attributes:
        load_vars: The ``Load`` expressions of global variables.
        store_vars: The ``Store`` statements to global variables.
        depends_on_external: Whether the walked code depends on data from outside the function.
    """

    def __init__(
        self,
        nodes_dict: dict[tuple[int, int | None], Block],
        srda,
        intermediate_global_vars: dict[int, set[Load]],
    ):
        super().__init__()
        self.depends_on_external: bool = False

        self.nodes_dict = nodes_dict
        self.intermediate_global_vars = intermediate_global_vars
        self.srda = srda

        self.load_vars = []
        self.store_vars = []

        self.replace_vvar = []

    def _handle_Load(
        self,
        expr_idx: int,
        expr: Load,
        stmt_idx: int,
        stmt: Statement,
        block: Block | None,
    ):
        # *vvar_X, or *(vvar_X + 5), or *(global_addr), or *(vvar_X + 6 + vvar_y * 7)
        if isinstance(expr.addr, Const):
            # *(global_addr)
            self.depends_on_external = True
            if expr.addr.value not in self.intermediate_global_vars:
                self.load_vars.append(expr)
            else:
                self.load_vars += list(
                    _expand(self.intermediate_global_vars, expr.addr.value, set())
                )
        else:
            walker = ExprDependsOnExternal(self.nodes_dict, self.srda)
            walker.walk_expression(expr.addr)
            self.depends_on_external |= walker.depends_on_external & (
                not walker.depends_on_stack
            )
            self.load_vars.append(expr)

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None):
        if isinstance(stmt.addr, Const):
            # *(global_addr)
            self.depends_on_external = True
            self.store_vars.append(stmt)
        else:
            walker = ExprDependsOnExternal(self.nodes_dict, self.srda)
            walker.walk_expression(stmt.addr)
            self.depends_on_external |= walker.depends_on_external & (
                not walker.depends_on_stack
            )
            if walker.replace_vvar:
                for old_vvar, new_vvar in walker.replace_vvar:
                    stmt_new = stmt.replace(old_vvar, new_vvar)
                    if stmt_new[0]:
                        self.store_vars.append(stmt_new[1])
            else:
                self.store_vars.append(stmt)

    def _handle_VirtualVariable(
        self,
        expr_idx: int,
        expr: VirtualVariable,
        stmt_idx: int,
        stmt: Statement,
        block: Block | None,
    ):
        walker = ExprDependsOnExternal(self.nodes_dict, self.srda)
        walker.walk_expression(expr)
        self.depends_on_external |= walker.depends_on_external & (
            not walker.depends_on_stack
        )
        if walker.replace_vvar:
            old_vvar, new_vvar = walker.replace_vvar[0]
            if isinstance(new_vvar, VirtualVariable):
                self.load_vars.append(new_vvar)
            # elif isinstance(new_vvar, Load):
            #     # self._handle_Load(expr_idx, new_vvar, stmt_idx, stmt, block)
            #     self.load_vars.append(new_vvar)
            else:
                self.walk_expression(new_vvar)
            # self.replace_vvar.append((old_vvar, new_vvar))
        #             stmt_new = stmt.replace(old_vvar, new_vvar)
        #             if stmt_new[0]:
        #                 self.store_vars.append(stmt_new[1])
        else:
            self.load_vars.append(expr)


class OperandExtractor(AILBlockViewer):
    """
    Collect the sub-expressions of an AIL expression, in ``operands``.
    """

    def __init__(self, expr: Expression):
        super().__init__()
        self.expr = expr
        self.operands = []
        self.walk_expression(expr, None, None, None)

    def _handle_expr(
        self,
        expr_idx: int,
        expr: Expression,
        stmt_idx: int,
        stmt: Statement | None,
        block: Block | None,
    ) -> Any:
        if expr is not self.expr:
            self.operands.append(expr)
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


class GlobalVarType(Enum):
    """
    How a :class:`GlobalVar` is addressed.
    """

    #: An absolute address.
    GLOBAL = 1
    #: An offset from a pointer held in a virtual variable (e.g. the program's data pointer argument).
    VVAR = 2


class GlobalVar:
    """
    A global variable accessed by the scan cycle.

    Args:
        addr: The absolute address (:attr:`GlobalVarType.GLOBAL`) or the offset from ``vvar_base``
            (:attr:`GlobalVarType.VVAR`).
        size: The size in bytes.
        var_type: How the variable is addressed.
        vvar_base: The virtual variable holding the base pointer, for :attr:`GlobalVarType.VVAR`.

    Examples:
        >>> GlobalVar(0x43A598, 1, GlobalVarType.GLOBAL)
        <Global 0x43a598:1 bytes>
        >>> GlobalVar(0x43A598, 1, GlobalVarType.GLOBAL) == GlobalVar(0x43A598, 1, GlobalVarType.GLOBAL)
        True
    """

    def __init__(
        self,
        addr: int,
        size: int,
        var_type: GlobalVarType,
        vvar_base: VirtualVariable = None,
    ):
        self.addr = addr
        self.size = size
        self.type = var_type
        self.vvar_base = vvar_base

    def __eq__(self, other):
        return (
            isinstance(other, GlobalVar)
            and self.addr == other.addr
            and self.size == other.size
            and self.type == other.type
            and self.vvar_base == other.vvar_base
        )

    def __hash__(self):
        return hash((GlobalVar, self.addr, self.size))

    def __repr__(self):
        if self.type == GlobalVarType.GLOBAL:
            return f"<Global {hex(self.addr)}:{self.size} bytes>"

        return f"<VVAR {self.vvar_base} offset {hex(self.addr)}: {self.size} bytes>"


def extract_variable_from_expr(
    expr: Expression,
    nodes_dict: dict[tuple[int, int | None], Block],
    srda: SRDAModel,
    intermediate_global_vars: dict[int, set[Load]],
) -> ConditionWalker:
    """
    Walk an AIL expression with a :class:`ConditionWalker` and return the walker.

    Examples:
        >>> walker = extract_variable_from_expr(cond, nodes_dict, srda.model, {})  # doctest: +SKIP
        >>> walker.load_vars  # doctest: +SKIP
    """
    cond_parser = ConditionWalker(nodes_dict, srda, intermediate_global_vars)
    cond_parser.walk_expression(expr, None, None, None)

    # if cond_parser.depends_on_external and cond_parser.replace_vvar:
    # (old_vvar, new_vvar) = cond_parser.replace_vvar[0]
    # expr_new = expr.replace(old_vvar, new_vvar)

    return cond_parser


def extract_addr_from_stmt(
    stmt: Statement,
    nodes_dict: dict[tuple[int, int | None], Block],
    srda: SRDAModel,
    intermediate_global_vars,
):
    """
    Walk an AIL statement with a :class:`ConditionWalker` and return the walker.

    Examples:
        >>> walker = extract_addr_from_stmt(stmt, nodes_dict, srda.model, {})  # doctest: +SKIP
        >>> walker.store_vars  # doctest: +SKIP
    """
    cond_parser = ConditionWalker(nodes_dict, srda, intermediate_global_vars)
    cond_parser.walk_statement(stmt, None)

    return cond_parser


def trace_global_vars(
    nodes: list, dec, srda, gv_dict: DefaultDict[GlobalVar, list], proj
):
    """
    Record the reads and writes of global variables in one decompiled scan cycle function.

    Reads are taken from the conditions of conditional jumps (the variables that decide control flow), and writes
    from stores to global memory. Each access is appended to ``gv_dict[variable]`` as ``("read", instruction
    address)`` or ``("write", instruction address)``.

    Args:
        nodes: The function's AIL blocks, in quasi-topological order.
        dec: The decompiler result of the function.
        srda: The SSA reaching definitions model of the function.
        gv_dict: The accesses recorded so far, updated in place.
        proj: The angr project.

    Examples:
        >>> from collections import defaultdict
        >>> from angr.utils.graph import GraphUtils
        >>> gv_dict = defaultdict(list)  # doctest: +SKIP
        >>> nodes = GraphUtils.quasi_topological_sort_nodes(dec.clinic.cc_graph)  # doctest: +SKIP
        >>> trace_global_vars(nodes, dec, srda.model, gv_dict, proj)  # doctest: +SKIP
    """
    func_virtual_vars = [var[0] for var in dec.clinic.arg_vvars.values()]

    # parse all conditions from each conditional jump statement
    conds = []
    for node in nodes:
        if not node.statements:
            continue
        last_stmt = node.statements[-1]
        # if node.addr == 0x42d05e:
        #     print(last_stmt)
        if isinstance(last_stmt, ConditionalJump):
            cond = last_stmt.condition
            conds.append(cond)

    print(conds)
    # collect all assignments between global variables
    intermediate_global_vars = defaultdict(
        set
    )  # addr of the intermediate variable to other global variables
    for node in nodes:
        for stmt in node.statements:
            if isinstance(stmt, Store) and isinstance(stmt.addr, Const):
                data = stmt.data
                if isinstance(data, Load) and isinstance(data.addr, Const):
                    intermediate_global_vars[stmt.addr.value].add(data)
                if isinstance(data, (BinaryOp, Convert)):
                    oe = OperandExtractor(data)
                    for arg in oe.operands:
                        if isinstance(arg, Load) and isinstance(arg.addr, Const):
                            intermediate_global_vars[stmt.addr.value].add(arg)
                if (
                    isinstance(data, Call)
                    and isinstance(data.target, Const)
                    and proj.kb.functions.contains_addr(data.target.value)
                ):
                    the_func = proj.kb.functions[data.target.value]
                    # TODO: Handle other types of functions
                    if the_func.name == "OR__BOOL__BOOL" and len(data.args) == 5:
                        # arg[3] | arg[4]
                        arg3, arg4 = data.args[3], data.args[4]
                        if isinstance(arg3, Convert):
                            arg3 = arg3.operand
                        if isinstance(arg4, Convert):
                            arg4 = arg4.operand
                        if (
                            isinstance(arg3, Load)
                            and isinstance(arg3.addr, Const)
                            and isinstance(arg4, Load)
                            and isinstance(arg4.addr, Const)
                        ):
                            intermediate_global_vars[stmt.addr.value] |= {arg3, arg4}

    nodes_dict = {(node.addr, node.idx): node for node in nodes}

    for node in nodes:
        if not node.statements:
            continue
        if not node.statements:
            continue
        last_stmt = node.statements[-1]
        if isinstance(last_stmt, ConditionalJump):
            cond = last_stmt.condition
            cond_parser = extract_variable_from_expr(
                cond, nodes_dict, srda, intermediate_global_vars
            )
            if cond_parser.depends_on_external:
                global_vars = cond_parser.load_vars
                for expr in global_vars:
                    if isinstance(expr, VirtualVariable):
                        # reading function argument as value
                        continue
                    if isinstance(expr.addr, Const):
                        gv = GlobalVar(expr.addr.value, expr.size, GlobalVarType.GLOBAL)
                        gv_dict[gv].append(("read", last_stmt.tags.get("ins_addr")))
                    elif isinstance(expr.addr, VirtualVariable):
                        # vvar_0
                        gv = GlobalVar(
                            addr=0,
                            size=expr.size,
                            var_type=GlobalVarType.VVAR,
                            vvar_base=expr.addr,
                        )
                        gv_dict[gv].append(("read", last_stmt.tags.get("ins_addr")))
                    elif isinstance(expr.addr, Load):
                        # [vvar_0 + 0x8]+x
                        continue
                    elif expr.addr.op == "Add":
                        # vvar_0 + x
                        vvar_base = expr.addr.operands[0]
                        vvar_offset = expr.addr.operands[1]
                        if isinstance(vvar_offset, Const):
                            gv = GlobalVar(
                                vvar_offset.value,
                                expr.size,
                                GlobalVarType.VVAR,
                                vvar_base,
                            )
                            gv_dict[gv].append(("read", last_stmt.tags.get("ins_addr")))
                        else:
                            print(vvar_offset)
                    elif expr.addr.op == "Sub" and expr.addr.operands[1].sign_bit == 1:
                        # optimize sub
                        vvar_base = expr.addr.operands[0]
                        vvar_offset_value = (
                            1 << expr.addr.operands[1].bits
                        ) - expr.addr.operands[1].value
                        if isinstance(vvar_offset, Const):
                            gv = GlobalVar(
                                vvar_offset_value,
                                expr.size,
                                GlobalVarType.VVAR,
                                vvar_base,
                            )
                            gv_dict[gv].append(("read", stmt.tags.get("ins_addr")))
                        else:
                            print(vvar_offset)
                    else:
                        print(expr)
                        continue

        for stmt in node.statements:
            if isinstance(stmt, Store):
                stmt_parser = extract_addr_from_stmt(
                    stmt, nodes_dict, srda, intermediate_global_vars
                )
                if stmt_parser.depends_on_external:
                    global_vars = stmt_parser.store_vars
                    for expr in global_vars:
                        if isinstance(expr.addr, Const):
                            gv = GlobalVar(
                                stmt.addr.value, stmt.size, GlobalVarType.GLOBAL
                            )
                            gv_dict[gv].append(("write", stmt.tags.get("ins_addr")))
                        elif isinstance(expr.addr, VirtualVariable):
                            # vvar_0
                            gv = GlobalVar(
                                addr=0,
                                size=stmt.size,
                                var_type=GlobalVarType.VVAR,
                                vvar_base=expr.addr,
                            )
                            gv_dict[gv].append(("write", stmt.tags.get("ins_addr")))
                        elif expr.addr.op == "Add":
                            vvar_base = expr.addr.operands[0]
                            vvar_offset = expr.addr.operands[1]
                            gv = GlobalVar(
                                vvar_offset.value,
                                stmt.size,
                                GlobalVarType.VVAR,
                                vvar_base,
                            )
                            gv_dict[gv].append(("write", stmt.tags.get("ins_addr")))
                        elif (
                            expr.addr.op == "Sub"
                            and expr.addr.operands[1].sign_bit == 1
                        ):
                            # optimize sub
                            vvar_base = expr.addr.operands[0]
                            vvar_offset_value = (
                                1 << expr.addr.operands[1].bits
                            ) - expr.addr.operands[1].value
                            gv = GlobalVar(
                                vvar_offset_value,
                                stmt.size,
                                GlobalVarType.VVAR,
                                vvar_base,
                            )
                            gv_dict[gv].append(("write", stmt.tags.get("ins_addr")))
                        else:
                            raise NotImplementedError(
                                f"unsupported store address expression: {expr.addr}"
                            )

    """
            global_vars = extract_variable_from_expr(cond)
            for expr in global_vars:
                if isinstance(expr, Load):
                    if isinstance(expr.addr, Const):   # fixme: need better way to check if global
                        gv = GlobalVar(expr.addr.value, expr.size, GlobalVarType.GLOBAL)
                        gv_dict[gv].append(("read", last_stmt.tags.get("ins_addr")))
                    else:
                        # Check if variable depends on function argument
                        for virtual_var in func_virtual_vars:
                            if expr.addr.likes(virtual_var):
                                gv = GlobalVar(expr.addr.varid, expr.size, GlobalVarType.VVAR)
                                gv_dict[gv].append(("read", last_stmt.tags.get("ins_addr")))

        for stmt in node.statements:
            if isinstance(stmt, Store):
                if isinstance(stmt.addr, Const):
                    gv = GlobalVar(stmt.addr.value, stmt.size, GlobalVarType.GLOBAL)
                    gv_dict[gv].append(("write", stmt.tags.get("ins_addr")))
                else:
                    # Check if variable depends on function argument
                        for virtual_var in func_virtual_vars:
                            if stmt.addr.likes(virtual_var):
                                gv = GlobalVar(stmt.addr.varid, stmt.size, GlobalVarType.VVAR)
                                gv_dict[gv].append(("write", stmt.tags.get("ins_addr")))
    """


def analyse_statevars(binary_path: str = None, funcs: List[Union[int, str]] = None):
    """
    Find and print the state variable candidates of a PLC program.

    A state variable stores the current state of the program's state machine across scan cycles, so the scan cycle
    reads it (to decide what to do) before it writes it (to move to the next state). For every global variable that
    the scan cycle functions access, accesses are ordered by instruction address; the variable is a candidate if
    the first access is a read and it is also written somewhere.

    When the scan cycle takes a pointer to the program's data as its first argument, the pointer's value is found
    from the binary's symbols and injected into the decompiled code, so accesses through it are resolved to global
    addresses. Offsets are printed relative to that data block: they are the ``address`` values to put in the
    environment model (see :mod:`taveren.env_model`).

    Prints the decompiled code, the recorded accesses and one line per candidate.

    Args:
        binary_path: The path of the PLC binary.
        funcs: Addresses of the scan cycle function(s).

    Examples:
        Find the state variables of the water tank (output from ``experiments/statevars/logs``, decompiled code and
        access lists omitted):

        >>> analyse_statevars("tests/fixtures/water_tank/build/water_tank.so", [0x41C24A])  # doctest: +SKIP
        ...
        State variable candidate <Global 0x43a598:1 bytes>,  offset = 0x8
    """

    proj = angr.Project(binary_path)
    cfg = proj.analyses.CFGFast(
        show_progressbar=True, force_smart_scan=False, normalize=True
    )
    proj.analyses.CompleteCallingConventions(
        analyze_callsites=True, prioritize_func_addrs=funcs, skip_other_funcs=True
    )

    # which registers the data pointer is stored for the scan cycle function, and what the addresses are
    data_args: dict[str, int] = {}

    #     # # rover
    #     # proj = angr.Project("statevars/arduino-b_flash_R7FA4M1AB.hex", main_opts = {"arch": "ARMCortexM", "endness": "Iend_LE", "entry_point": 0x1f35}, auto_load_libs=False)
    #     # cfg = proj.analyses.CFGFast(force_smart_scan=False, show_progressbar=True, normalize=True)
    #     #
    #     # funcs = [
    #     #     0x46f1,  # update_position
    #     #     0x4ec9,  # loop
    #     # ]
    #
    #     # # copter x86
    #     # binary_path = "/home/bonnie/PLCRCA/arducopter/arducopter_nobuildin"
    #     # proj = angr.Project(binary_path)
    #     # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    #     # funcs = [0x47e1cc]
    #
    # water tank
    # binary_path = '/home/bonnie/SMCheck/fbd_examples/water_tank_sfc_one_sensor/build/water_tank_sfc_one_sensor.so'
    # proj = angr.Project(binary_path)
    # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    # funcs = [0x4235C9]
    #
    #     # # water tank fbd
    #     # # State variable candidate <VVAR vvar_0 offset 0x8: 1 bytes>
    #     # binary_path = '/home/bonnie/SMCheck/fbd_examples/CPS Binary Analysis/water_tank/build/water_tank.so'
    #     # proj = angr.Project(binary_path)
    #     # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    #     # funcs = [0x41C24A]
    #
    # # car wash arm
    # binary_path = "/home/bonnie/SMCheck/binaries/carwash-mkr1010-g.elf"
    # proj = angr.Project(binary_path)
    # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    # proj.analyses.CompleteCallingConventions(
    #     analyze_callsites=True,
    #     prioritize_func_addrs=[0x2da5],
    #     skip_other_funcs=True
    # )
    # funcs = [0x2da5]

    # # warehouse lifter
    # binary_path = '/home/bonnie/SMCheck/fbd_examples/warehouse_lift/build/warehouse_lift.so'
    # proj = angr.Project(binary_path)
    # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    # funcs = [0x423A54]
    #
    #     # # Water Tank WT.3
    #     # binary_path = '/home/bonnie/SMCheck/fbd_examples/water_tank_sfc_two_sesnors/build/water_tank_sfc_two_sesnors.so'
    #     # proj = angr.Project(binary_path)
    #     # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    #     # funcs = [0x42359A]
    #
    #     # # Packaging
    #     # binary_path = '/home/bonnie/SMCheck/fbd_examples/packaging_sfc/build/packaging_sfc.so'
    #     # proj = angr.Project(binary_path)
    #     # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    #     # funcs = [0x4236C0]
    #
    #     # packaging 2 mips
    #     binary_path = "/home/bonnie/SMCheck/fbd_examples/packaging_sfc/build/packaging_sfc_mips.so"
    #     proj = angr.Project(binary_path)
    #     cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    #     proj.analyses.CompleteCallingConventions(
    #         analyze_callsites=True,
    #         prioritize_func_addrs=[0x416634],
    #         skip_other_funcs=True
    #     )
    #     funcs = [0x416634]

    #     packaging 3 ppc
    # binary_path = "/home/bonnie/SMCheck/fbd_examples/packaging_sfc/build/packaging_sfc_powerpc.so"
    # proj = angr.Project(binary_path)
    # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    # proj.analyses.CompleteCallingConventions(
    #     analyze_callsites=True,
    #     prioritize_func_addrs=[0x41689c],
    #     skip_other_funcs=True
    # )
    # funcs = [0x41689c]
    #
    # # Traffic Light TL.4
    # binary_path = os.path.join(base_dir, 'PLCRCA/traffic_light_addsensor_x86-64/Traffic_Light_addsensor_x86-64.so')
    # proj = angr.Project(binary_path)
    # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    # proj.analyses.CompleteCallingConventions(
    #     analyze_callsites=True,
    #     prioritize_func_addrs=[0x42C83D],
    #     skip_other_funcs=True
    # )
    # funcs = [0x42C83D]

    # # # Traffic Light TL.5
    # binary_path = '/home/bonnie/PLCRCA/Traffic_Light_Short_Ped/build/Traffic_Light_Short_Ped.so'
    # proj = angr.Project(binary_path)
    # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    # proj.analyses.CompleteCallingConventions(
    #     analyze_callsites=True,
    #     prioritize_func_addrs=[0x42BF53],
    #     skip_other_funcs=True
    # )
    # funcs = [0x42BF53]

    # # Traffic Light TL.6
    # binary_path = '/home/bonnie/PLCRCA/arm32/Traffic_Light_Short_Ped/build/Traffic_Light_Short_Ped.so'
    # proj = angr.Project(binary_path)
    # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    # proj.analyses.CompleteCallingConventions(
    #     analyze_callsites=True,
    #     prioritize_func_addrs=[0x42C698],
    #     skip_other_funcs=True
    # )
    # funcs = [0x42C698]

    # # Traffic Light TL.7
    # binary_path = '/home/bonnie/PLCRCA/Traffic_Light_both_green/build/Traffic_Light_both_green.so'
    # proj = angr.Project(binary_path)
    # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    # proj.analyses.CompleteCallingConventions(
    #         analyze_callsites=True,
    #         prioritize_func_addrs=[0x42BF53],
    #         skip_other_funcs=True
    #     )
    # funcs = [0x42BF53]

    #
    # # Traffic Light TL.8
    # binary_path = '/home/bonnie/PLCRCA/Traffic_Light_short_orange/build/Traffic_Light_short_orange.so'
    # proj = angr.Project(binary_path)
    # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    # proj.analyses.CompleteCallingConventions(
    #     analyze_callsites=True,
    #     prioritize_func_addrs=[0x42BF53],
    #     skip_other_funcs=True
    # )
    # funcs = [0x42BF53]
    #
    # # traffic light beremiz TL.9
    # proj = angr.Project("/home/bonnie/PLCRCA/Traffic_Light_original/build/Traffic_Light_original.so")
    # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    # proj.analyses.CompleteCallingConventions(
    #     analyze_callsites=True,
    #     prioritize_func_addrs=[0x42c034],
    #     skip_other_funcs=True
    # )  # so the function return type becomes void instead of long long
    # funcs = [0x42C034]

    #
    #     # # Traffic Light TL.10
    #     # binary_path = '/home/bonnie/PLCRCA/arm32/Traffic_Light/build/Traffic_Light.so'
    #     # proj = angr.Project(binary_path)
    #     # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    #     # funcs = [0x42C698]
    #
    #     # # Traffic Light TL.11
    #     # binary_path = '/home/bonnie/PLCRCA/arm32/blinky_sf/MyBlinky.elf'
    #     # proj = angr.Project(binary_path)
    #     # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    #     # funcs = [cfg.kb.functions['MyBlinky_step'].addr]
    #
    # # Launch Abort System Abort.1
    # binary_path = '../binaries/sf_launchabort.exe'
    # proj = angr.Project(binary_path, auto_load_libs=False)
    # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    # funcs = [0x4015CD]
    # data_args = {"r8": 0x408B40 + 0x10, "r9": 0x408B60 + 0x38}
    #
    #     # Oven Oven.1
    #     # binary_path = '/home/bonnie/PLCRCA/normal_oven/arduino_build_normaloven/normal_oven.ino.elf'
    #     # proj = angr.Project(binary_path)
    #     # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    #     # funcs = [cfg.kb.functions["loop"].addr]
    #
    # # Vending Vend.1
    # binary_path = '/home/bonnie/SMCheck/vending machine/arduino_build_389120/vending_machine.ino.elf'
    # proj = angr.Project(binary_path)
    # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    # funcs = [cfg.kb.functions["_Z14vendingMachinev"].addr]
    #
    # Elevator Elev.1
    # binary_path = '/home/bonnie/SMCheck/elevator/test/project/elevator.ino.elf'
    # proj = angr.Project(binary_path)
    # cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    # funcs = [cfg.kb.functions["loop"].addr]
    # #
    # #     # # simple traffic light
    # #     # proj = angr.Project("/home/bonnie/PLCRCA/simple_traffic_light/arduino_build_61535/simple_traffic_light.ino.elf")
    # #     # cfg = proj.analyses.CFGFast(show_progressbar=False, normalize=True)
    # #     # funcs = [0x2139, 0x24fd, 0x2455, 0x236d]
    #

    # Hack: we replace all mov xxx, [rbp-0x68] with mov xxx, &RESOURCE1__MAIN_INSTANCE in this function
    import capstone

    initial_arg_values = {}
    if not data_args:
        symbols = ["RESOURCE1__MAIN_INSTANCE", "RES0__INSTANCE0"]
        arg_symbol = next(
            (proj.loader.find_symbol(s) for s in symbols if proj.loader.find_symbol(s)),
            None,
        )
        if arg_symbol:
            data_addr = arg_symbol.rebased_addr
            match proj.arch.name:
                case "AMD64":
                    first_arg = "rdi"
                case "ARM":
                    first_arg = "r0"
                case "MIPS32":
                    first_arg = "a0"
                case "PPC32":
                    first_arg = "r3"
                case _:
                    raise NotImplementedError(
                        f"Architecture {proj.arch.name} not supported yet."
                    )
            data_args = {first_arg: data_addr}

    if data_args:
        stack_offset = None
        if proj.arch.name == "AMD64":
            for func_addr in funcs:
                func = cfg.kb.functions[func_addr]
                # find where the data pointer(s) are stored on stack
                for data_reg, data_addr in data_args.items():
                    entry_block = proj.factory.block(func_addr)
                    for inst in entry_block.capstone.insns:
                        if (
                            inst.mnemonic == "mov"
                            and inst.operands[0].type == capstone.x86.X86_OP_MEM
                            and inst.operands[0].mem.base == capstone.x86.X86_REG_RBP
                            and inst.operands[1].type == capstone.x86.X86_OP_REG
                            and inst.operands[1].reg
                            == getattr(capstone.x86, f"X86_REG_{data_reg.upper()}")
                        ):
                            stack_offset = inst.operands[0].mem.disp
                            break
                    if stack_offset is not None:
                        for block_addr in func.block_addrs_set:
                            for insn in proj.factory.block(block_addr).capstone.insns:
                                if (
                                    insn.mnemonic == "mov"
                                    and insn.operands[0].type == capstone.x86.X86_OP_REG
                                    and insn.operands[1].type == capstone.x86.X86_OP_MEM
                                    and insn.operands[1].mem.base
                                    == capstone.x86.X86_REG_RBP
                                    and insn.operands[1].mem.disp == stack_offset
                                ):
                                    dst = insn.op_str.split(",")[0]
                                    initial_arg_values[insn.address] = {dst: data_addr}
        elif "ARM" in proj.arch.name:
            for func_addr in funcs:
                func = cfg.kb.functions[func_addr]
                # find where r0 is stored on stack
                entry_block = proj.factory.block(func_addr)
                for inst in entry_block.capstone.insns:
                    if inst.mnemonic == "str":
                        # first store instruction to store r0
                        if (
                            inst.operands[0].type == capstone.arm.ARM_OP_REG
                            and inst.operands[0].reg == capstone.arm.ARM_REG_R0
                            and inst.operands[1].type == capstone.arm.ARM_OP_MEM
                        ):
                            stack_mem_base = inst.operands[1].mem.base
                            stack_offset = inst.operands[1].mem.disp
                            break
                if stack_offset is not None:
                    for block_addr in func.block_addrs_set:
                        for insn in proj.factory.block(block_addr).capstone.insns:
                            if (
                                insn.mnemonic == "ldr"
                                and insn.operands[0].type == capstone.arm.ARM_OP_REG
                                and insn.operands[1].type == capstone.arm.ARM_OP_MEM
                                and insn.operands[1].mem.base == stack_mem_base
                                and insn.operands[1].mem.disp == stack_offset
                            ):
                                dst = insn.op_str.split(",")[0]
                                initial_arg_values[insn.address] = {dst: data_addr}
        elif "MIPS" in proj.arch.name:
            for func_addr in funcs:
                func = cfg.kb.functions[func_addr]
                # find where a0 is stored on stack
                entry_block = proj.factory.block(func_addr)
                for inst in entry_block.capstone.insns:
                    if (
                        inst.mnemonic == "sw"
                        and inst.operands[0].type == capstone.mips.MIPS_OP_REG
                        and inst.operands[0].reg == capstone.mips.MIPS_REG_A0
                        and inst.operands[1].type == capstone.mips.MIPS_OP_MEM
                    ):
                        stack_mem_base = inst.operands[1].mem.base
                        stack_offset = inst.operands[1].mem.disp
                        break
                if stack_offset is not None:
                    for block_addr in func.block_addrs_set:
                        for insn in proj.factory.block(block_addr).capstone.insns:
                            if (
                                insn.mnemonic == "lw"
                                and insn.operands[0].type == capstone.mips.MIPS_OP_REG
                                and insn.operands[1].type == capstone.mips.MIPS_OP_MEM
                                and insn.operands[1].mem.base == stack_mem_base
                                and insn.operands[1].mem.disp == stack_offset
                            ):
                                dst = insn.op_str.split(",")[0].strip("$")
                                initial_arg_values[insn.address] = {dst: data_addr}
        elif "PPC32" in proj.arch.name:
            for func_addr in funcs:
                func = cfg.kb.functions[func_addr]
                # find where r3 (the first arg) is stored on stack
                entry_block = proj.factory.block(func_addr)
                stack_mem_base = None
                for inst in entry_block.capstone.insns:
                    if (
                        inst.mnemonic == "stw"
                        and inst.operands[0].type == capstone.ppc.PPC_OP_REG
                        and inst.operands[0].reg == capstone.ppc.PPC_REG_R3
                        and inst.operands[1].type == capstone.ppc.PPC_OP_MEM
                    ):
                        stack_mem_base = inst.operands[1].mem.base
                        stack_offset = inst.operands[1].mem.disp
                        break
                assert stack_mem_base is not None
                if stack_offset is not None:
                    for block_addr in func.block_addrs_set:
                        for insn in proj.factory.block(block_addr).capstone.insns:
                            if (
                                insn.mnemonic == "lwz"
                                and insn.operands[0].type == capstone.ppc.PPC_OP_REG
                                and insn.operands[1].type == capstone.ppc.PPC_OP_MEM
                                and insn.operands[1].mem.base == stack_mem_base
                                and insn.operands[1].mem.disp == stack_offset
                            ):
                                dst = insn.op_str.split(",")[0]
                                initial_arg_values[insn.address] = {dst: data_addr}
        else:
            print("Architecture not supported for initial argument value injection.")
            pass

    def _hooked_convert_vex(o, block):
        # convert it regardless
        converted = Clinic._convert_vex_original(o, block)
        touched_insn_addrs = set()
        for idx, stmt in reversed(list(enumerate(converted.statements))):
            if (
                stmt.tags.get("ins_addr") not in touched_insn_addrs
                and stmt.tags.get("ins_addr") in initial_arg_values
            ):
                for reg_name, reg_value in initial_arg_values[
                    stmt.tags.get("ins_addr")
                ].items():
                    reg_offset, reg_size = proj.arch.registers[reg_name]
                    reg_bits = reg_size * 8
                    reg = Register(
                        o._ail_manager.next_atom(),
                        reg_offset,
                        reg_bits,
                        ins_addr=stmt.tags.get("ins_addr"),
                    )
                    val = Const(
                        o._ail_manager.next_atom(),
                        reg_value,
                        reg_bits,
                        ins_addr=stmt.tags.get("ins_addr"),
                    )
                    set_reg_stmt = Assignment(
                        o._ail_manager.next_atom(),
                        reg,
                        val,
                        ins_addr=stmt.tags.get("ins_addr"),
                    )
                    converted.statements.insert(idx + 1, set_reg_stmt)
                    touched_insn_addrs.add(stmt.tags.get("ins_addr"))
        return converted

    if initial_arg_values:
        # hack
        from angr.analyses.decompiler.clinic import Clinic

        Clinic._convert_vex_original = Clinic._convert_vex
        Clinic._convert_vex = _hooked_convert_vex

    gv_dict = defaultdict(list)
    for func_addr in funcs:
        func = cfg.kb.functions[func_addr]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        print(dec.codegen.text)
        # ddg = proj.analyses.DataDependencyGraph()
        # traverse the graph to get all conditions and variables used

        func_args = {vvar for vvar, _ in dec.clinic.arg_vvars.values()}
        srda = proj.analyses.SReachingDefinitions(
            subject=func, func_graph=dec.clinic.cc_graph, func_args=func_args
        )
        # srda.model.all_vvar_uses[0]
        # print({node.addr: node for node in dec.clinic.graph}[0x42c055].statements[1])

        # nodes = list(dec.clinic.graph)
        nodes = GraphUtils.quasi_topological_sort_nodes(dec.clinic.cc_graph)
        trace_global_vars(nodes, dec, srda.model, gv_dict, proj)

    from pprint import pprint

    pprint(gv_dict)
    print("--" * 20)

    statevar_candidates = []

    all_var_bases = list(data_args.values())

    if "sf_launchabort.exe" in proj.filename:
        # special hack for this binary because it abuses "is_Abort" as an output variable as well
        blacklist_blocks = [(0x40160D, 0x401634)]
        for gv, accesses in list(gv_dict.items()):
            accesses = [
                a
                for a in accesses
                if not any(start <= a[1] <= end for start, end in blacklist_blocks)
            ]
            gv_dict[gv] = accesses

    if "oven" in proj.filename:
        # skip the error handling code is at the beginning of the scan cycle
        blaclist_blocks = [(0x21C3, 0x2301)]
        for gv, accesses in list(gv_dict.items()):
            accesses = [
                a
                for a in accesses
                if not any(start <= a[1] <= end for start, end in blaclist_blocks)
            ]
            gv_dict[gv] = accesses

    for gv, accesses in gv_dict.items():
        if accesses:
            sorted_accesses = sorted(accesses, key=lambda x: x[1])
            if sorted_accesses[0][0] == "read" and any(
                a[0] == "write" for a in sorted_accesses
            ):
                offsets = [gv.addr - base for base in all_var_bases if gv.addr >= base]
                print(
                    f"State variable candidate {gv},  offset = {hex(min(offsets) if offsets else gv.addr)}"
                )
                statevar_candidates.append(gv)


def run_one(
    binary_path: str,
    funcs: List[Union[int, str]],
    binary_opts: Optional[Dict[str, Any]] = None,
    out_file: Optional[str] = None,
) -> bool:
    """
    Run :func:`analyse_statevars`, resolving function names and optionally logging to a file.

    This is the ``taveren-statevars`` command.

    Args:
        binary_path: The path of the PLC binary.
        funcs: The scan cycle function(s), as addresses or symbol names. Names are replaced with addresses in
            place.
        binary_opts: Loader options for the main binary (``main_opts`` of ``angr.Project``), e.g. for raw firmware.
        out_file: Write all output (stdout and stderr) to this file instead.

    Returns:
        ``True`` on success, ``False`` if the analysis raised an exception (the traceback is printed), or ``None``
        if a function name is not found.

    Examples:
        >>> run_one("tests/fixtures/water_tank/build/water_tank.so", [0x41C24A], out_file="statevars.log")  # doctest: +SKIP
        True

        Raw firmware needs loader options:

        >>> run_one("firmware.bin", ["loop"],
        ...         binary_opts={"backend": "blob", "arch": "ARMCortexM", "entry_point": 0x1F35})  # doctest: +SKIP
    """
    saved_stdout = None
    saved_stderr = None
    success = True

    if binary_opts:
        proj = angr.Project(binary_path, main_opts=binary_opts, auto_load_libs=False)
    else:
        proj = angr.Project(binary_path)

    cfg = proj.analyses.CFGFast(force_smart_scan=False, normalize=True)
    valid = True
    for ind, func in enumerate(funcs):
        if type(func) is str:
            if func not in cfg.kb.functions:
                print(f"{func} not found in CFG KB")
                valid = False
            else:
                funcs[ind] = cfg.kb.functions[func].addr

    if not valid:
        return

    if out_file:
        fh_out = open(out_file, "w")
        saved_stdout = sys.stdout
        sys.stdout = fh_out
        saved_stderr = sys.stderr
        sys.stderr = fh_out

    try:
        analyse_statevars(binary_path, funcs)
        # gv_dict = defaultdict(list)
        # for func_addr in funcs:
        #     func = cfg.kb.functions[func_addr]
        #     dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        #     print(dec.codegen.text)
        #     # traverse the graph to get all conditions and variables used
        #
        #     func_args = {vvar for vvar, _ in dec.clinic.arg_vvars.values()}
        #     srda = proj.analyses.SReachingDefinitions(subject=func, func_graph=dec.clinic.graph, func_args=func_args)
        #     # srda.model.all_vvar_uses[0]
        #     # print({node.addr: node for node in dec.clinic.graph}[0x42c055].statements[1])
        #
        #     # nodes = list(dec.clinic.graph)
        #     nodes = GraphUtils.quasi_topological_sort_nodes(dec.clinic.cc_graph)
        #     trace_global_vars(nodes, dec, srda.model, gv_dict, proj)

        # from pprint import pprint
        # pprint(gv_dict)
        # print("--"*20)
        #
        # for gv, accesses in gv_dict.items():
        #     if accesses and accesses[0][0] == "read" and any(a[0] == "write" for a in accesses):
        #         print(f"State variable candidate {gv},  offset = {hex(gv.addr - proj.loader.find_symbol("RESOURCE1__MAIN_INSTANCE").rebased_addr)}")
    except:
        print(traceback.format_exc())
        success = False

    if out_file:
        sys.stdout = saved_stdout
        saved_stdout = None
        sys.stderr = saved_stderr
        saved_stderr = None
        fh_out.close()

    return success


def main(argv: list[str] | None = None) -> None:
    """
    Entry point of ``taveren-statevars``. Exits with status 1 if the analysis fails.

    Args:
        argv: The command-line arguments, without the program name. Defaults to ``sys.argv[1:]``.

    Examples:
        >>> main(["tests/fixtures/water_tank/build/water_tank.so", "0x41C24A", "-o", "statevars.log"])  # doctest: +SKIP

        is the same as running::

            taveren-statevars tests/fixtures/water_tank/build/water_tank.so 0x41C24A -o statevars.log
    """
    parser = argparse.ArgumentParser(
        prog="taveren-statevars",
        description="Identify state variable candidates in the scan cycle of a PLC binary.",
    )
    parser.add_argument("binary", help="path to the PLC binary to analyze")
    parser.add_argument(
        "funcs",
        nargs="+",
        help="scan cycle function(s), as hex addresses (0x...) or symbol names",
    )
    parser.add_argument(
        "-o", "--out", help="write the analysis log to this file instead of stdout"
    )
    args = parser.parse_args(argv)

    funcs = [int(f, 16) if f.startswith("0x") else f for f in args.funcs]
    if not run_one(args.binary, funcs, out_file=args.out):
        sys.exit(1)


if __name__ == "__main__":
    main()
