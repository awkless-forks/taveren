from __future__ import annotations
from enum import Enum
import os
import pathlib
import sys
sys.setrecursionlimit(50000)
import traceback
from typing import Any, DefaultDict, Dict, List, Optional, Union
from collections import defaultdict

from angr.ailment import Block
from angr.ailment.block_walker import AILBlockWalkerBase
from angr.ailment.statement import ConditionalJump, Statement, Store, Assignment, Call, Assignment
from angr.ailment.expression import Expression, Load, Const, VirtualVariable, Convert, BinaryOp, Register
import angr
from angr.utils.graph import GraphUtils
from angr.analyses.s_reaching_definitions import SRDAModel
from angr.code_location import ExternalCodeLocation
from angr.ailment import Block
from angr.ailment.block_walker import AILBlockWalkerBase
from angr.ailment.statement import ConditionalJump, Statement, Store, Assignment, Call
from angr.ailment.expression import Expression, Load, Const, VirtualVariable, Convert, BinaryOp


base_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../../")



class ExprDependsOnExternal(AILBlockWalkerBase):
    def __init__(self, nodes_dict: dict[tuple[int, int | None], Block], srda):
        super().__init__()
        self.depends_on_external: bool = False
        self.depends_on_stack: bool = False

        self.nodes_dict = nodes_dict
        self.srda = srda

        self.replace_vvar = [ ]

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        if expr.category == 1:  # stack
            self.depends_on_stack = True
        if expr.varid in self.srda.all_vvar_definitions:
            def_loc = self.srda.all_vvar_definitions[expr.varid]
            if isinstance(def_loc, ExternalCodeLocation):
                # it's external!
                self.depends_on_external = True
            else:
                def_stmt = self.nodes_dict[(def_loc.block_addr,def_loc.block_idx)].statements[def_loc.stmt_idx]
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


def _expand(intermediate_global_vars: dict[int, set[Load]], addr: int, seen: set[Load]) -> set[Load]:
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


class ConditionWalker(AILBlockWalkerBase):
    def __init__(self, nodes_dict: dict[tuple[int, int | None], Block], srda, intermediate_global_vars: dict[int, set[Load]]):
        super().__init__()
        self.depends_on_external: bool = False

        self.nodes_dict = nodes_dict
        self.intermediate_global_vars = intermediate_global_vars
        self.srda = srda

        self.load_vars = [ ]
        self.store_vars = [ ]

        self.replace_vvar = [ ]

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Block | None):
        # *vvar_X, or *(vvar_X + 5), or *(global_addr), or *(vvar_X + 6 + vvar_y * 7)
        if isinstance(expr.addr, Const):
            # *(global_addr)
            self.depends_on_external = True
            if expr.addr.value not in self.intermediate_global_vars:
                self.load_vars.append(expr)
            else:
                self.load_vars += list(_expand(self.intermediate_global_vars, expr.addr.value, set()))
        else:
            walker = ExprDependsOnExternal(self.nodes_dict, self.srda)
            walker.walk_expression(expr.addr)
            self.depends_on_external |= walker.depends_on_external & (not walker.depends_on_stack)
            self.load_vars.append(expr)

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None):
        if isinstance(stmt.addr, Const):
            # *(global_addr)
            self.depends_on_external = True
            self.store_vars.append(stmt)
        else:
            walker = ExprDependsOnExternal(self.nodes_dict, self.srda)
            walker.walk_expression(stmt.addr)
            self.depends_on_external |= walker.depends_on_external & (not walker.depends_on_stack)
            if walker.replace_vvar:
                for (old_vvar, new_vvar) in walker.replace_vvar:
                    stmt_new = stmt.replace(old_vvar, new_vvar)
                    if stmt_new[0]:
                        self.store_vars.append(stmt_new[1])
            else:
                self.store_vars.append(stmt)

    def _handle_VirtualVariable(
            self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        # import ipdb; ipdb.set_trace()
        walker = ExprDependsOnExternal(self.nodes_dict, self.srda)
        walker.walk_expression(expr)
        self.depends_on_external |= walker.depends_on_external & (not walker.depends_on_stack)
        if walker.replace_vvar:
            (old_vvar, new_vvar) = walker.replace_vvar[0]
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


class OperandExtractor(AILBlockWalkerBase):
    def __init__(self, expr: Expression):
        super().__init__()
        self.expr = expr
        self.operands = []
        self.walk_expression(expr, None, None, None)

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if expr is not self.expr:
            self.operands.append(expr)
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


class GlobalVarType(Enum):
    GLOBAL = 1
    VVAR = 2


class GlobalVar:
    def __init__(self, addr: int, size: int, var_type: GlobalVarType, vvar_base: VirtualVariable = None):
        self.addr = addr
        self.size = size
        self.type = var_type
        self.vvar_base = vvar_base

    def __eq__(self, other):
        return isinstance(other, GlobalVar) and self.addr == other.addr and self.size == other.size and self.type == other.type and self.vvar_base == other.vvar_base

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
    cond_parser = ConditionWalker(nodes_dict, srda, intermediate_global_vars)
    cond_parser.walk_expression(expr, None, None, None)

    # if cond_parser.depends_on_external and cond_parser.replace_vvar:
    #     import ipdb; ipdb.set_trace()
        # (old_vvar, new_vvar) = cond_parser.replace_vvar[0]
        # expr_new = expr.replace(old_vvar, new_vvar)

    return cond_parser

def extract_addr_from_stmt(stmt:Statement,
                           nodes_dict: dict[tuple[int, int | None], Block],
                           srda: SRDAModel,
                           intermediate_global_vars,
                           ):
    cond_parser = ConditionWalker(nodes_dict, srda, intermediate_global_vars)
    cond_parser.walk_statement(stmt, None)

    return  cond_parser


def trace_global_vars(nodes: list, dec, srda, gv_dict: DefaultDict[GlobalVar, list], proj):
    func_virtual_vars = [var[0] for var in dec.clinic.arg_vvars.values()]

    # parse all conditions from each conditional jump statement
    conds = [ ]
    for node in nodes:
        if not node.statements:
            continue
        last_stmt = node.statements[-1]
        # if node.addr == 0x42d05e:
        #     print(last_stmt)
        #     import ipdb; ipdb.set_trace()
        if isinstance(last_stmt, ConditionalJump):
            cond = last_stmt.condition
            conds.append(cond)

    print(conds)
    # import ipdb; ipdb.set_trace()
    # collect all assignments between global variables
    intermediate_global_vars = defaultdict(set)  # addr of the intermediate variable to other global variables
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
                if isinstance(data, Call) and isinstance(data.target, Const) and proj.kb.functions.contains_addr(data.target.value):
                    the_func = proj.kb.functions[data.target.value]
                    # TODO: Handle other types of functions
                    if the_func.name == "OR__BOOL__BOOL" and len(data.args) == 5:
                        # arg[3] | arg[4]
                        arg3, arg4 = data.args[3], data.args[4]
                        if isinstance(arg3, Convert):
                            arg3 = arg3.operand
                        if isinstance(arg4, Convert):
                            arg4 = arg4.operand
                        if isinstance(arg3, Load) and isinstance(arg3.addr, Const) and isinstance(arg4, Load) and isinstance(arg4.addr, Const):
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
            cond_parser = extract_variable_from_expr(cond, nodes_dict, srda, intermediate_global_vars)
            if cond_parser.depends_on_external:
                # import ipdb; ipdb.set_trace()
                global_vars = cond_parser.load_vars
                for expr in global_vars:
                    if isinstance(expr, VirtualVariable):
                        # reading function argument as value
                        continue
                    if isinstance(expr.addr, Const):
                        gv = GlobalVar(expr.addr.value, expr.size, GlobalVarType.GLOBAL)
                        gv_dict[gv].append(("read", last_stmt.ins_addr))
                    elif isinstance(expr.addr, VirtualVariable):
                        # vvar_0
                        gv = GlobalVar(addr=0, size=expr.size, var_type=GlobalVarType.VVAR, vvar_base=expr.addr)
                        gv_dict[gv].append(("read", last_stmt.ins_addr))
                    elif isinstance(expr.addr, Load):
                        # [vvar_0 + 0x8]+x
                        continue
                    elif expr.addr.op == "Add":
                        # vvar_0 + x
                        # import ipdb; ipdb.set_trace()
                        vvar_base = expr.addr.operands[0]
                        vvar_offset = expr.addr.operands[1]
                        if isinstance(vvar_offset, Const):
                            gv = GlobalVar(vvar_offset.value, expr.size, GlobalVarType.VVAR, vvar_base)
                            gv_dict[gv].append(("read", last_stmt.ins_addr))
                        else:
                            print(vvar_offset)
                    elif expr.addr.op == "Sub" and expr.addr.operands[1].sign_bit == 1:
                        # optimize sub
                        vvar_base = expr.addr.operands[0]
                        vvar_offset_value = (1 << expr.addr.operands[1].bits) - expr.addr.operands[1].value
                        if isinstance(vvar_offset, Const):
                            gv = GlobalVar(vvar_offset_value, expr.size, GlobalVarType.VVAR, vvar_base)
                            gv_dict[gv].append(("read", stmt.ins_addr))
                        else:
                            print(vvar_offset)
                    else:
                        print(expr)
                        continue
                        # import ipdb; ipdb.set_trace()

        for stmt in node.statements:
            if isinstance(stmt, Store):
                stmt_parser = extract_addr_from_stmt(stmt, nodes_dict, srda, intermediate_global_vars)
                if stmt_parser.depends_on_external:
                    global_vars = stmt_parser.store_vars
                    for expr in global_vars:
                        if isinstance(expr.addr, Const):
                            gv = GlobalVar(stmt.addr.value, stmt.size, GlobalVarType.GLOBAL)
                            gv_dict[gv].append(("write", stmt.ins_addr))
                        elif isinstance(expr.addr, VirtualVariable):
                            # vvar_0
                            gv = GlobalVar(addr=0, size=stmt.size, var_type=GlobalVarType.VVAR, vvar_base=expr.addr)
                            gv_dict[gv].append(("write", stmt.ins_addr))
                        elif expr.addr.op == "Add":
                            vvar_base = expr.addr.operands[0]
                            vvar_offset = expr.addr.operands[1]
                            gv = GlobalVar(vvar_offset.value, stmt.size, GlobalVarType.VVAR, vvar_base)
                            gv_dict[gv].append(("write", stmt.ins_addr))
                        elif expr.addr.op == "Sub" and expr.addr.operands[1].sign_bit == 1:
                            # optimize sub
                            vvar_base = expr.addr.operands[0]
                            vvar_offset_value = (1 << expr.addr.operands[1].bits) - expr.addr.operands[1].value
                            gv = GlobalVar(vvar_offset_value, stmt.size, GlobalVarType.VVAR, vvar_base)
                            gv_dict[gv].append(("write", stmt.ins_addr))
                        else:
                            import ipdb; ipdb.set_trace()


    """
            global_vars = extract_variable_from_expr(cond)
            for expr in global_vars:
                if isinstance(expr, Load):
                    if isinstance(expr.addr, Const):   # fixme: need better way to check if global
                        gv = GlobalVar(expr.addr.value, expr.size, GlobalVarType.GLOBAL)
                        gv_dict[gv].append(("read", last_stmt.ins_addr))
                    else:
                        # Check if variable depends on function argument
                        for virtual_var in func_virtual_vars:
                            if expr.addr.likes(virtual_var):
                                gv = GlobalVar(expr.addr.varid, expr.size, GlobalVarType.VVAR)
                                gv_dict[gv].append(("read", last_stmt.ins_addr))

        for stmt in node.statements:
            if isinstance(stmt, Store):
                if isinstance(stmt.addr, Const):
                    gv = GlobalVar(stmt.addr.value, stmt.size, GlobalVarType.GLOBAL)
                    gv_dict[gv].append(("write", stmt.ins_addr))
                else:
                    # Check if variable depends on function argument
                        for virtual_var in func_virtual_vars:
                            if stmt.addr.likes(virtual_var):
                                gv = GlobalVar(stmt.addr.varid, stmt.size, GlobalVarType.VVAR)
                                gv_dict[gv].append(("write", stmt.ins_addr))
    """


def analyse_statevars(binary_path: str=None, funcs: List[Union[int, str]]=None):

    proj = angr.Project(binary_path)
    cfg = proj.analyses.CFGFast(show_progressbar=True, force_smart_scan=False, normalize=True)
    proj.analyses.CompleteCallingConventions(
        analyze_callsites=True,
        prioritize_func_addrs=funcs,
        skip_other_funcs=True
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
        arg_symbol = next((proj.loader.find_symbol(s) for s in symbols if proj.loader.find_symbol(s)), None)
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
                    raise NotImplementedError(f"Architecture {proj.arch.name} not supported yet.")
            data_args = {
                first_arg: data_addr
            }

    if data_args:
        stack_offset = None
        if proj.arch.name == "AMD64":
            for func_addr in funcs:
                func = cfg.kb.functions[func_addr]
                # find where the data pointer(s) are stored on stack
                for data_reg, data_addr in data_args.items():
                    entry_block = proj.factory.block(func_addr)
                    for inst in entry_block.capstone.insns:
                        if (inst.mnemonic == "mov"
                                and inst.operands[0].type == capstone.x86.X86_OP_MEM
                                and inst.operands[0].mem.base == capstone.x86.X86_REG_RBP
                                and inst.operands[1].type == capstone.x86.X86_OP_REG
                                and inst.operands[1].reg == getattr(capstone.x86, f"X86_REG_{data_reg.upper()}")
                        ):
                            stack_offset = inst.operands[0].mem.disp
                            break
                    if stack_offset is not None:
                        for block_addr in func.block_addrs_set:
                            for insn in proj.factory.block(block_addr).capstone.insns:
                                if insn.mnemonic == "mov" and insn.operands[0].type == capstone.x86.X86_OP_REG and insn.operands[1].type == capstone.x86.X86_OP_MEM and insn.operands[1].mem.base == capstone.x86.X86_REG_RBP and insn.operands[1].mem.disp == stack_offset:
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
                        # import ipdb; ipdb.set_trace()
                        if inst.operands[0].type == capstone.arm.ARM_OP_REG and inst.operands[0].reg == capstone.arm.ARM_REG_R0 and inst.operands[1].type == capstone.arm.ARM_OP_MEM:
                            stack_mem_base = inst.operands[1].mem.base
                            stack_offset = inst.operands[1].mem.disp
                            break
                if stack_offset is not None:
                    for block_addr in func.block_addrs_set:
                        for insn in proj.factory.block(block_addr).capstone.insns:
                            if (insn.mnemonic == "ldr"
                                    and insn.operands[0].type == capstone.arm.ARM_OP_REG
                                    and insn.operands[1].type == capstone.arm.ARM_OP_MEM
                                    and insn.operands[1].mem.base == stack_mem_base
                                    and insn.operands[1].mem.disp == stack_offset):
                                dst = insn.op_str.split(",")[0]
                                initial_arg_values[insn.address] = {dst: data_addr}
        elif "MIPS" in proj.arch.name:
            for func_addr in funcs:
                func = cfg.kb.functions[func_addr]
                # find where a0 is stored on stack
                entry_block = proj.factory.block(func_addr)
                for inst in entry_block.capstone.insns:
                    if (inst.mnemonic == "sw"
                            and inst.operands[0].type == capstone.mips.MIPS_OP_REG
                            and inst.operands[0].reg == capstone.mips.MIPS_REG_A0
                            and inst.operands[1].type == capstone.mips.MIPS_OP_MEM):
                        stack_mem_base = inst.operands[1].mem.base
                        stack_offset = inst.operands[1].mem.disp
                        break
                if stack_offset is not None:
                    for block_addr in func.block_addrs_set:
                        for insn in proj.factory.block(block_addr).capstone.insns:
                            if (insn.mnemonic == "lw"
                                    and insn.operands[0].type == capstone.mips.MIPS_OP_REG
                                    and insn.operands[1].type == capstone.mips.MIPS_OP_MEM
                                    and insn.operands[1].mem.base == stack_mem_base
                                    and insn.operands[1].mem.disp == stack_offset):
                                dst = insn.op_str.split(",")[0].strip("$")
                                initial_arg_values[insn.address] = {dst: data_addr}
        elif "PPC32" in proj.arch.name:
            for func_addr in funcs:
                func = cfg.kb.functions[func_addr]
                # find where r3 (the first arg) is stored on stack
                entry_block = proj.factory.block(func_addr)
                stack_mem_base = None
                for inst in entry_block.capstone.insns:
                    if (inst.mnemonic == "stw"
                            and inst.operands[0].type == capstone.ppc.PPC_OP_REG
                            and inst.operands[0].reg == capstone.ppc.PPC_REG_R3
                            and inst.operands[1].type == capstone.ppc.PPC_OP_MEM):
                        stack_mem_base = inst.operands[1].mem.base
                        stack_offset = inst.operands[1].mem.disp
                        break
                assert stack_mem_base is not None
                if stack_offset is not None:
                    for block_addr in func.block_addrs_set:
                        for insn in proj.factory.block(block_addr).capstone.insns:
                            if (insn.mnemonic == "lwz"
                                    and insn.operands[0].type == capstone.ppc.PPC_OP_REG
                                    and insn.operands[1].type == capstone.ppc.PPC_OP_MEM
                                    and insn.operands[1].mem.base == stack_mem_base
                                    and insn.operands[1].mem.disp == stack_offset):
                                dst = insn.op_str.split(",")[0]
                                initial_arg_values[insn.address] = {dst: data_addr}
        else:
            print("Architecture not supported for initial argument value injection.")
            # import ipdb; ipdb.set_trace()
            pass



    def _hooked_convert_vex(o, block):
        # convert it regardless
        converted = Clinic._convert_vex_original(o, block)
        touched_insn_addrs = set()
        for idx, stmt in reversed(list(enumerate(converted.statements))):
            if stmt.ins_addr not in touched_insn_addrs and stmt.ins_addr in initial_arg_values:
                for reg_name, reg_value in initial_arg_values[stmt.ins_addr].items():
                    reg_offset, reg_size = proj.arch.registers[reg_name]
                    reg_bits = reg_size * 8
                    reg = Register(o._ail_manager.next_atom(), None, reg_offset, reg_bits, ins_addr=stmt.ins_addr)
                    val = Const(o._ail_manager.next_atom(), None, reg_value, reg_bits, ins_addr=stmt.ins_addr)
                    set_reg_stmt = Assignment(o._ail_manager.next_atom(), reg, val, ins_addr=stmt.ins_addr)
                    converted.statements.insert(idx + 1, set_reg_stmt)
                    touched_insn_addrs.add(stmt.ins_addr)
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
        # import ipdb; ipdb.set_trace()
        # traverse the graph to get all conditions and variables used

        func_args = {vvar for vvar, _ in dec.clinic.arg_vvars.values()}
        srda = proj.analyses.SReachingDefinitions(subject=func, func_graph=dec.clinic.cc_graph, func_args=func_args)
        # srda.model.all_vvar_uses[0]
        # print({node.addr: node for node in dec.clinic.graph}[0x42c055].statements[1])

        # nodes = list(dec.clinic.graph)
        nodes = GraphUtils.quasi_topological_sort_nodes(dec.clinic.cc_graph)
        trace_global_vars(nodes, dec, srda.model, gv_dict, proj)

    from pprint import pprint
    pprint(gv_dict)
    print("--"*20)

    statevar_candidates = []

    all_var_bases = list(data_args.values())

    if "sf_launchabort.exe" in proj.filename:
        # special hack for this binary because it abuses "is_Abort" as an output variable as well
        blacklist_blocks = [(0x40160D, 0x401634)]
        for gv, accesses in list(gv_dict.items()):
            accesses = [a for a in accesses if not any(start <= a[1] <= end for start, end in blacklist_blocks)]
            gv_dict[gv] = accesses

    if "oven" in proj.filename:
        # skip the error handling code is at the beginning of the scan cycle
        blaclist_blocks = [(0x21c3, 0x2301)]
        for gv, accesses in list(gv_dict.items()):
            accesses = [a for a in accesses if not any(start <= a[1] <= end for start, end in blaclist_blocks)]
            gv_dict[gv] = accesses

    for gv, accesses in gv_dict.items():
        if accesses:
            sorted_accesses = sorted(accesses, key=lambda x: x[1])
            if sorted_accesses[0][0] == "read" and any(a[0] == "write" for a in sorted_accesses):
                offsets = [gv.addr - base for base in all_var_bases if gv.addr >= base]
                print(f"State variable candidate {gv},  offset = {hex(min(offsets) if offsets else gv.addr)}")
                # import ipdb; ipdb.set_trace()
                statevar_candidates.append(gv)

    # import ipdb; ipdb.set_trace()


def run_one(binary_path: str, funcs: List[Union[int, str]], binary_opts: Optional[Dict[str, Any]] = None, out_file: Optional[str] = None) -> bool:
    saved_stdout = None
    saved_stderr = None
    success = True

    if binary_opts:
        proj = angr.Project(binary_path, main_opts = binary_opts, auto_load_libs=False)
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
        fh_out = open(out_file, 'w')
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
        #     # import ipdb; ipdb.set_trace()
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

    if not out_file:
        import ipdb; ipdb.set_trace()
    else:
        sys.stdout = saved_stdout
        saved_stdout = None
        sys.stderr = saved_stderr
        saved_stderr = None
        fh_out.close()

    return success


# def run_all():
#     logs_dir = pathlib.Path(os.getcwd()) / "logs4"
#     logs_dir.mkdir(exist_ok=True, parents=True)
#
#     # # Rover
#     # print("Running Rover...", end="", flush=True)
#     # if run_one("/home/bonnie/SMCheck/statevars/arduino-b_flash_R7FA4M1AB.hex", [0x46f1, 0x4ec9], binary_opts={"arch": "ARMCortexM", "endness": "Iend_LE", "entry_point": 0x1f35},
#     #             out_file=logs_dir / "rover.out"):
#     #     print("done.")
#     # else:
#     #     print("error.")
#     #
#     # # Copter x86
#     # print("Running Copter...", end="", flush=True)
#     # if run_one("/home/bonnie/PLCRCA/arducopter/arducopter_nobuildin", [0x47e1cc], out_file=logs_dir / "copter.out"):
#     #     print("done.")
#     # else:
#     #     print("error.")
#
#     # Traffic light beremiz
#     print("Running Traffic light (beremiz)...", end="", flush=True)
#     if run_one("/home/bonnie/PLCRCA/Traffic_Light_original/build/Traffic_Light_original.so", [0x42C034],
#                out_file=logs_dir / "traffic-light-beremiz.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # water tank
#     print("Running water tank...", end="", flush=True)
#     if run_one('/home/bonnie/SMCheck/fbd_examples/water_tank_sfc_one_sensor/build/water_tank_sfc_one_sensor.so',
#                [0x4235C9], out_file=logs_dir / "water-tank.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # water tank fbd
#     # # State variable candidate <VVAR vvar_0 offset 0x8: 1 bytes>
#     print("Running water tank fbd...", end="", flush=True)
#     if run_one('/home/bonnie/SMCheck/fbd_examples/CPS Binary Analysis/water_tank/build/water_tank.so', [0x41C24A],
#                out_file=logs_dir / "water-tank-fbd.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # warehouse lifter
#     print("Running lifter...", end="", flush=True)
#     if run_one('/home/bonnie/SMCheck/fbd_examples/warehouse_lift/build/warehouse_lift.so', [0x423A54],
#                out_file=logs_dir / "warehouse-lifter.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # Water Tank WT.3
#     print("Running water tank(WT.3)...", end="", flush=True)
#     if run_one('/home/bonnie/SMCheck/fbd_examples/water_tank_sfc_two_sesnors/build/water_tank_sfc_two_sesnors.so', [0x436870],
#                out_file=logs_dir / "water-tank-wt3.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # Packaging
#     print("Running Packaging...", end="", flush=True)
#     if run_one('/home/bonnie/SMCheck/fbd_examples/packaging_sfc/build/packaging_sfc.so', [0x4236C0],
#                out_file=logs_dir / "packaging.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # packaging mips
#     print("Running Packaging MIPS...", end="", flush=True)
#     if run_one('/home/bonnie/SMCheck/fbd_examples/packaging_sfc/build/packaging_sfc_mips.so', [0x416634],
#                out_file=logs_dir / "packaging-mips.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # packaging ppc32
#     print("Running Packaging PPC32...", end="", flush=True)
#     if run_one('/home/bonnie/SMCheck/fbd_examples/packaging_sfc/build/packaging_sfc_powerpc.so', [0x41689c],
#                out_file=logs_dir / "packaging-ppc32.out"):
#         print("done.")
#
#     # Traffic Light TL.4
#     print("Running traffic light (TL.4)...", end="", flush=True)
#     if run_one('/home/bonnie/PLCRCA/traffic_light_addsensor_x86-64/Traffic_Light_addsensor_x86-64.so', [0x42C83D],
#                out_file=logs_dir / "traffic-light-tl4.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # Traffic Light TL.5
#     print("Running traffic light (TL.5)...", end="", flush=True)
#     if run_one('/home/bonnie/PLCRCA/test/Traffic_Light_Short_Ped.so', [0x40d640],
#                out_file=logs_dir / "traffic-light-tl5.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # Traffic Light TL.6
#     print("Running traffic light (TL.6)...", end="", flush=True)
#     if run_one('/home/bonnie/PLCRCA/arm32/Traffic_Light_Short_Ped/build/Traffic_Light_Short_Ped.so', [0x42C698],
#                out_file=logs_dir / "traffic-light-tl6.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # Traffic Light TL.7
#     print("Running traffic light (TL.7)...", end="", flush=True)
#     if run_one('/home/bonnie/PLCRCA/Traffic_Light_both_green/build/Traffic_Light_both_green.so', [0x42BF53],
#                out_file=logs_dir / "traffic-light-tl7.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # Traffic Light TL.8
#     print("Running traffic light (TL.8)...", end="", flush=True)
#     if run_one('/home/bonnie/PLCRCA/Traffic_Light_short_orange/build/Traffic_Light_short_orange.so', [0x42BF53],
#                out_file=logs_dir / "traffic-light-tl8.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # Traffic Light TL.10
#     print("Running traffic light (TL.10)...", end="", flush=True)
#     if run_one('/home/bonnie/PLCRCA/arm32/Traffic_Light/build/Traffic_Light.so', [0x42C698],
#                out_file=logs_dir / "traffic-light-tl10.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # Traffic Light TL.11
#     print("Running traffic light (TL.11)...", end="", flush=True)
#     if run_one('/home/bonnie/PLCRCA/arm32/blinky_sf/MyBlinky.elf', ['MyBlinky_step'],
#                out_file=logs_dir / "traffic-light-tl11.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # Launch Abort System Abort.1
#     print("Running abort system(Abort.1)...", end="", flush=True)
#     if run_one('/home/bonnie/SMCheck/binaries/sf_launchabort.exe', [0x4015CD],
#                out_file=logs_dir / "launch-abort-system-abort1.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # Oven Oven.1
#     print("Running Oven (Oven.1)...", end="", flush=True)
#     if run_one('/home/bonnie/PLCRCA/normal_oven/arduino_build_normaloven/normal_oven.ino.elf', ["loop"],
#                out_file=logs_dir / "oven-oven1.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # Vending Vend.1
#     print("Running Vending Machine (Vend.1)...", end="", flush=True)
#     if run_one('/home/bonnie/SMCheck/vending machine/arduino_build_389120/vending_machine.ino.elf', ["_Z14vendingMachinev"],
#                out_file=logs_dir / "vending-vend1.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # Elevator Elev.1
#     print("Running Elevator (Elev.1)...", end="", flush=True)
#     if run_one('/home/bonnie/SMCheck/elevator/test/project/elevator.ino.elf', ["loop"],
#                out_file=logs_dir / "elevator-elev1.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # # elevator avr
#     # print("Running Elevator (Elev.2) AVR...", end="", flush=True)
#     # if run_one('/home/bonnie/SMCheck/elevator/test/project/elevator_uno_O0.ino.elf', ["loop"],
#     #             out_file=logs_dir / "elevator-elev2-avr.out"):
#     #       print("done.")
#     # else:
#     #         print("error.")
#
#
#     # # simple traffic light
#     # print("Running simple traffic light...", end="", flush=True)
#     # if run_one("/home/bonnie/PLCRCA/simple_traffic_light/arduino_build_61535/simple_traffic_light.ino.elf", [0x2139, 0x24fd, 0x2455, 0x236d],
#     #            out_file=logs_dir / "simple-traffic-light.out"):
#     #     print("done.")
#     # else:
#     #     print("error.")
#
#     # carwash
#     print("Running Car Wash (CarW.1)...", end="", flush=True)
#     if run_one('/home/bonnie/SMCheck/fbd_examples/car_wash_sfc/car_wash_3/build/car_wash.so', [0x438395],
#                 out_file=logs_dir / "car-wash.out"):
#         print("done.")
#     else:
#         print("error.")
#
#     # car wash arm
#     print("Running Car Wash (CarW.2) ARM...", end="", flush=True)
#     if run_one('/home/bonnie/SMCheck/binaries/carwash-mkr1010-g.elf', [0x2da5],
#                 out_file=logs_dir / "car-wash-arm.out"):
#         print("done.")
#     else:
#         print("error.")

if __name__ == "__main__":

    # # binary_path = '/home/bonnie/PLCRCA/traffic_light_addsensor_x86-64/Traffic_Light_addsensor_x86-64.so'
    # # funcs = [0x42C83D]
    # # analyse_statevars(binary_path, funcs)
    analyse_statevars()
    # run_all()

