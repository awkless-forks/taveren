from itertools import count
from typing import Optional, Dict, Set, Callable, Any, TYPE_CHECKING

from angr import claripy
import pprint
from angr.sim_options import (
    NO_CROSS_INSN_OPT,
    SYMBOL_FILL_UNCONSTRAINED_MEMORY,
    SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
)
from angr.state_plugins.inspect import BP_BEFORE, BP_AFTER, BP
from angr.analyses.analysis import AnalysesHub
from taveren.state_graph_recovery import (
    ExpressionLogger,
    SliceGenerator,
    MultiDiGraph_DedupeEdge,
    StateGraphRecoveryBase,
)

if TYPE_CHECKING:
    from angr import SimState
    from angr.knowledge_plugins.functions import Function
    from taveren import AbstractStateFields


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
        self._ret_trap: int = 0x1F37FF4A
        self.printstate = printstate
        self.patch_callback = patch_callback

        self._time_addr = time_addr
        self.low_sensor_info = inputs["LOW_LEVEL_SENSOR"]
        self.high_sensor_info = inputs["HIGH_LEVEL_SENSOR"]
        self.low_sensor = None
        self.high_sensor = None
        self._tv_sec_var = None
        self._temperature = None
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
        symbolic_low_sensor = self._symbolize_low_sensor(init_state)
        symbolic_high_sensor = self._symbolize_high_sensor(init_state)

        # setup inspection points to catch where expressions are created
        all_vars = set(symbolic_abstate_fields.values())
        all_vars |= set(symbolic_time_counters.values())
        all_vars | set(symbolic_low_sensor.values())
        all_vars | set(symbolic_high_sensor.values())
        slice_gen = SliceGenerator(all_vars, bp=None)
        expression_bp = slice_gen.install_expr_hook(init_state)

        # setup inspection points to catch where expressions are written to registers
        expression_logger = ExpressionLogger(
            self._expression_source, {v.args[0] for v in all_vars}
        )
        regwrite_bp = BP(
            when=BP_BEFORE, enabled=True, action=expression_logger.on_register_write
        )
        init_state.inspect.add_breakpoint("reg_write", regwrite_bp)
        memread_bp = BP(
            when=BP_AFTER, enabled=True, action=expression_logger.on_memory_read
        )
        init_state.inspect.add_breakpoint("mem_read", memread_bp)

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
                0,
                None,
                None,
                0,
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
                low_delta,
                low_constraint,
                low_src,
                high_delta,
                high_constraint,
                high_src,
            ) = state_queue.pop(0)
            print(
                prev_abs_state, low_delta, low_constraint, high_delta, high_constraint
            )
            if time_delta is None:
                pass
            else:
                # advance the time stamp as required
                self._advance_timecounter(prev_state, time_delta)
            if low_delta is not None:
                self._advance_low_sensor(prev_state, low_delta)
            if high_delta is not None:
                self._advance_high_sensor(prev_state, high_delta)

            # symbolically trace the state
            expression_bp.enabled = True
            next_state = self._traverse_one(prev_state)

            expression_bp.enabled = False

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
            absstate_to_slice[abs_state] = slice_gen.slice
            print("[.] There are %d nodes in the slice." % len(slice_gen.slice))

            transition = (
                prev_prev_abs,
                prev_abs_state,
                abs_state,
                low_delta,
                high_delta,
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
                low_delta=low_delta,
                low_constraint=low_constraint,
                low_src=low_src,
                high_delta=high_delta,
                high_constraint=high_constraint,
                high_src=high_src,
                label=f"low={low_delta}, high={high_delta}",
            )

            # discover time deltas
            # also discover what other input fields are used in the constraints
            time_delta_and_sources = self._discover_time_deltas(next_state)

            for delta, constraint, source in time_delta_and_sources:
                if source is None:
                    block_addr, stmt_idx = -1, -1
                else:
                    block_addr, stmt_idx = source
                print(
                    f"[.] Discovered a new time interval {delta} defined at {block_addr:#x}:{stmt_idx}"
                )

            # add new work states with deltas to queue
            for (low_delta, low_constraint, low_src), (
                high_delta,
                high_constraint,
                high_src,
            ) in self._discover_low_and_high_deltas(next_state):
                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(
                    new_state, self.fields
                )
                symbolic_time_counters = self._symbolize_timecounter(new_state)
                symbolic_low_sensor = self._symbolize_low_sensor(new_state)
                symbolic_high_sensor = self._symbolize_high_sensor(new_state)
                all_vars = set(symbolic_abstate_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                all_vars |= set(symbolic_low_sensor.values())
                all_vars |= set(symbolic_high_sensor.values())
                all_vars |= self.config_vars
                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                state_queue.append(
                    (
                        new_state,
                        abs_state_id,
                        abs_state,
                        prev_abs_state,
                        None,
                        None,
                        None,
                        low_delta,
                        low_constraint,
                        low_src,
                        high_delta,
                        high_constraint,
                        high_src,
                    )
                )

    def _traverse_one(self, state: "SimState", discover: bool = False):

        simgr = self.project.factory.simgr(state)

        while simgr.active:
            s = simgr.active[0]
            if not discover:
                if len(simgr.active) > 1:
                    raise RuntimeError(
                        "scan cycle execution forked into multiple active states"
                    )

            if s.addr == 0x41C2A5:
                print("CHECKING LOW SENSOR!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            if s.addr == 0x41C2B1:
                print("CHECKING HIGH SENSOR!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            if s.addr == 0x41C2BD:
                print("CHECKING PUMP!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            if s.addr == 0x41C2C9:
                print("PUMP ON!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            if s.addr == 0x41C2D0:
                print("PUMP OFF!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

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
        else:
            s = self.project.factory.blank_state(addr=self.func.addr)
            s.regs.rdi = 0xC0000000
            s.memory.store(0xC0000000, b"\x00" * 0x1000)

        # disable cross instruction optimization so that statement IDs in symbolic execution will match the ones used in
        # static analysis
        s.options[NO_CROSS_INSN_OPT] = True
        # disable warnings
        s.options[SYMBOL_FILL_UNCONSTRAINED_MEMORY] = True
        s.options[SYMBOL_FILL_UNCONSTRAINED_REGISTERS] = True

        if self.project.arch.call_pushes_ret:
            s.stack_push(claripy.BVV(self._ret_trap, self.project.arch.bits))
        else:
            # set up the link register for the return address
            s.regs.lr = self._ret_trap

        return s


AnalysesHub.register_default("StateGraphRecoveryTwoSensor", StateGraphRecoveryAnalysis)
