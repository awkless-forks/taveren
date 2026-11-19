from itertools import count
from typing import Optional, Dict, Set, Callable, Any, TYPE_CHECKING

from angr import claripy
import pprint
from angr.sim_options import (
    NO_CROSS_INSN_OPT,
    SYMBOL_FILL_UNCONSTRAINED_MEMORY,
    SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
)
from angr.analyses.analysis import AnalysesHub
from taveren.state_graph_recovery import MultiDiGraph_DedupeEdge, StateGraphRecoveryBase

if TYPE_CHECKING:
    from angr import SimState
    from angr.knowledge_plugins.functions import Function
    from .abstract_state import AbstractStateFields


class StateGraphRecoveryAnalysis(StateGraphRecoveryBase):
    """
    Traverses a function and derive a state graph with respect to given variables.
    """

    def __init__(
        self,
        func: "Function",
        fields: "AbstractStateFields",
        software: str,
        time_addr: int,
        temp_addr: int = None,
        init_state: Optional["SimState"] = None,
        inputs: Dict = None,
        fields_input: Optional[Any] = None,
        switch_on: Optional[Callable] = None,
        printstate: Optional[Callable] = None,
        config_vars: Optional[Set[claripy.ast.Base]] = None,
        patch_callback: Optional[Callable] = None,
    ):
        self.func = func
        self.fields = fields
        self.config_vars = config_vars if config_vars is not None else set()
        self.software = software
        self.init_state = init_state
        self.inputs = inputs
        self.fields_input = fields_input
        self._switch_on = switch_on
        self._ret_trap: int = 0x1F37FF4A if self.project.arch.name != "AVR" else 0xFFFE
        self.printstate = printstate
        self.patch_callback = patch_callback

        self._time_addr = time_addr
        self.btn1_info = inputs["btn1"]
        self.btn1 = None
        self.btn2_info = inputs["btn2"]
        self.btn2 = None
        self.btn3_info = inputs["btn3"]
        self.btn3 = None
        self.btn4_info = inputs["btn4"]
        self.btn4 = None
        self._tv_sec_var = None
        self.state_graph = None
        self._expression_source = {}
        self.traverse()

    def traverse(self):

        # create an empty state graph
        self.state_graph = MultiDiGraph_DedupeEdge()

        # make the initial state
        init_state = self._initialize_state(init_state=self.init_state)
        symbolic_abstate_fields = self._symbolize_var_fields(init_state, self.fields)
        symbolic_time_counters = self._symbolize_timecounter(init_state)

        # setup inspection points to catch where expressions are created
        all_vars = set(symbolic_abstate_fields.values())
        all_vars |= set(symbolic_time_counters.values())

        # Abstract state ID counter
        abs_state_id_ctr = count(0)

        abs_state = self.fields.generate_abstract_state(init_state)
        abs_state_id = next(abs_state_id_ctr)
        self.state_graph.add_node(
            (("NODE_CTR", abs_state_id),) + abs_state, outvars=dict(abs_state)
        )
        state_queue = [
            (
                init_state,
                abs_state_id,
                abs_state,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
        ]

        switched_on = False if self._switch_on else True
        known_transitions = list()
        known_states = dict()
        absstate_to_slice = {}
        while state_queue:
            (
                prev_state,
                prev_abs_state_id,
                prev_abs_state,
                prev_prev_abs,
                time_delta,
                time_delta_constraint,
                time_delta_src,
                btn1_delta,
                btn1_constraint,
                btn1_src,
                btn2_delta,
                btn2_constraint,
                btn2_src,
                btn3_delta,
                btn3_constraint,
                btn3_src,
                btn4_delta,
                btn4_constraint,
                btn4_src,
            ) = state_queue.pop(0)
            print(prev_abs_state, btn1_delta, btn2_delta, btn3_delta, btn4_delta)
            if time_delta is None:
                pass
            else:
                # advance the time stamp as required
                self._advance_timecounter(prev_state, time_delta)
            if btn1_delta is not None:
                self._set_btn1(prev_state, btn1_delta)
            if btn2_delta is not None:
                self._set_btn2(prev_state, btn2_delta)
            if btn3_delta is not None:
                self._set_btn3(prev_state, btn3_delta)
            if btn4_delta is not None:
                self._set_btn4(prev_state, btn4_delta)

            # symbolically trace the state
            next_state = self._traverse_one(prev_state)

            abs_state = self.fields.generate_abstract_state(next_state)

            if switched_on:
                if abs_state in known_states.keys():
                    abs_state_id = known_states[abs_state]
                else:
                    abs_state_id = next(abs_state_id_ctr)
                    known_states[abs_state] = abs_state_id
            else:
                abs_state_id = next(abs_state_id_ctr)

            print("[+] Discovered a new abstract state:")
            if self.printstate is None:
                pprint.pprint(abs_state)
            else:
                self.printstate(abs_state)

            transition = (
                prev_prev_abs,
                prev_abs_state,
                abs_state,
                btn1_delta,
                btn2_delta,
                btn3_delta,
                btn4_delta,
            )
            if switched_on and transition in known_transitions:
                continue

            known_transitions.append(transition)
            self.state_graph.add_node(
                (("NODE_CTR", abs_state_id),) + abs_state, outvars=dict(abs_state)
            )
            self.state_graph.add_edge(
                (("NODE_CTR", prev_abs_state_id),) + prev_abs_state,
                (("NODE_CTR", abs_state_id),) + abs_state,
                time_delta=time_delta,
                time_delta_constraint=time_delta_constraint,
                time_delta_src=time_delta_src,
                btn1_delta=btn1_delta,
                btn1_constraint=btn1_constraint,
                btn1_src=btn1_src,
                btn2_delta=btn2_delta,
                btn2_constraint=btn2_constraint,
                btn2_src=btn2_src,
                btn3_delta=btn3_delta,
                btn3_constraint=btn3_constraint,
                btn3_src=btn3_src,
                btn4_delta=btn4_delta,
                btn4_constraint=btn4_constraint,
                btn4_src=btn4_src,
                label=f"btn1={btn1_delta}\nbtn2={btn2_delta}\nbtn3={btn3_delta}\nbtn4={btn4_delta}",
            )

            # FIXME: This is a hack. We should fix it later.

            # add new work states with deltas to queue

            new_state = self._initialize_state(init_state=next_state)

            # re-symbolize input fields, time counters, and update slice generator
            symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
            symbolic_time_counters = self._symbolize_timecounter(new_state)
            all_vars = set(symbolic_abstate_fields.values())
            all_vars |= set(symbolic_time_counters.values())
            all_vars |= self.config_vars
            state_queue.append(
                (
                    new_state,
                    abs_state_id,
                    abs_state,
                    prev_abs_state,
                    None,
                    None,
                    None,
                    1,
                    None,
                    None,
                    0,
                    None,
                    None,
                    0,
                    None,
                    None,
                    0,
                    None,
                    None,
                )
            )
            state_queue.append(
                (
                    new_state,
                    abs_state_id,
                    abs_state,
                    prev_abs_state,
                    None,
                    None,
                    None,
                    0,
                    None,
                    None,
                    1,
                    None,
                    None,
                    0,
                    None,
                    None,
                    0,
                    None,
                    None,
                )
            )
            state_queue.append(
                (
                    new_state,
                    abs_state_id,
                    abs_state,
                    prev_abs_state,
                    None,
                    None,
                    None,
                    0,
                    None,
                    None,
                    0,
                    None,
                    None,
                    1,
                    None,
                    None,
                    0,
                    None,
                    None,
                )
            )
            state_queue.append(
                (
                    new_state,
                    abs_state_id,
                    abs_state,
                    prev_abs_state,
                    None,
                    None,
                    None,
                    0,
                    None,
                    None,
                    0,
                    None,
                    None,
                    0,
                    None,
                    None,
                    1,
                    None,
                    None,
                )
            )

    #             # find multiple deltas in one state
    #             # TODO: if there are multiple deltas, we need to AND them as the final constraint

    def _set_btn1(self, state: "SimState", delta) -> None:
        btn1_addr, btn1_sort, btn1_size = self.btn1_info
        if btn1_sort == "pin":
            state.globals[btn1_addr] = delta

    def _set_btn2(self, state: "SimState", delta) -> None:
        btn2_addr, btn2_sort, btn2_size = self.btn2_info
        if btn2_sort == "pin":
            state.globals[btn2_addr] = delta

    def _set_btn3(self, state: "SimState", delta) -> None:
        btn3_addr, btn3_sort, btn3_size = self.btn3_info
        if btn3_sort == "pin":
            state.globals[btn3_addr] = delta

    def _set_btn4(self, state: "SimState", delta) -> None:
        btn4_addr, btn4_sort, btn4_size = self.btn4_info
        if btn4_sort == "pin":
            state.globals[btn4_addr] = delta

    def _traverse_one(self, state: "SimState", discover: bool = False):

        simgr = self.project.factory.simgr(state)

        while simgr.active:
            s = simgr.active[0]
            if not discover:
                if len(simgr.active) > 1:
                    raise RuntimeError(
                        "scan cycle execution forked into multiple active states"
                    )

            if s.addr == 0x220D:
                print("button 4 pressed!!!!!!!!!!!!")
            if s.addr == 0x2259:
                print("button 3 pressed!!!!!!!!!!!!")
            if s.addr == 0x22F3:
                print("button 2 pressed!!!!!!!!!!!!")
            if s.addr == 0x2393:
                print("button 1 pressed!!!!!!!!!!!!")

            simgr.stash(
                lambda x: x.addr == self._ret_trap,
                from_stash="active",
                to_stash="finished",
            )

            simgr.step()

        if discover:
            return simgr.finished
        else:
            assert len(simgr.finished) == 1
            return simgr.finished[0]

    def _initialize_state(self, init_state=None) -> "SimState":
        if init_state is not None:
            s = init_state.copy()
            s.ip = self.func.addr
            s.globals[0x40] = 0
        else:
            s = self.project.factory.blank_state(addr=self.func.addr)
            s.regs.rdi = 0xC0000000
            s.memory.store(0xC0000000, b"\x00" * 0x1000)

        # disable cross instruction optimization so that statement IDs in symbolic execution will match the ones used in
        # static analysis
        s.options[NO_CROSS_INSN_OPT] = False
        # disable warnings
        s.options[SYMBOL_FILL_UNCONSTRAINED_MEMORY] = True
        s.options[SYMBOL_FILL_UNCONSTRAINED_REGISTERS] = True

        if self.project.arch.call_pushes_ret:
            if self.project.arch.name == "AVR":
                sp = s.regs.sp - 2
                s.regs.sp = sp
                ret_addr = claripy.BVV(self._ret_trap, 16)
                s.memory.store(
                    sp, ret_addr, endness=self.project.arch.memory_endness, size=2
                )
            else:
                s.stack_push(claripy.BVV(self._ret_trap, self.project.arch.bits))
        else:
            # set up the link register for the return address
            s.regs.lr = self._ret_trap

        return s


AnalysesHub.register_default("StateGraphRecoveryElevator", StateGraphRecoveryAnalysis)
