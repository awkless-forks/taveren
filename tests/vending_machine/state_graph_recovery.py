from itertools import count
from typing import Optional, List, Dict, Tuple, Set, Callable, Any, TYPE_CHECKING

import itertools
from angr import claripy
import pprint
from angr.sim_options import (
    NO_CROSS_INSN_OPT,
    SYMBOL_FILL_UNCONSTRAINED_MEMORY,
    SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
)
from angr.state_plugins.inspect import BP_BEFORE, BP
from angr.analyses.analysis import AnalysesHub
from taveren.state_graph_recovery import (
    ConstraintLogger,
    MultiDiGraph_DedupeEdge,
    StateGraphRecoveryBase,
)

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
        self._ret_trap: int = 0x1F37FF4A
        self.printstate = printstate
        self.patch_callback = patch_callback

        self._time_addr = time_addr
        self.dollar_info = inputs["dollar"]
        self.quarter_info = inputs["quarter"]
        self.dollar = None
        self.quarter = None
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
        symbolic_dollar = self._symbolize_dollar(init_state)
        symbolic_quarter = self._symbolize_quarter(init_state)

        # setup inspection points to catch where expressions are created
        all_vars = set(symbolic_abstate_fields.values())
        all_vars |= set(symbolic_time_counters.values())
        all_vars | set(symbolic_dollar.values())
        all_vars | set(symbolic_quarter.values())

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
                dollar_delta,
                dollar_constraint,
                dollar_src,
                quarter_delta,
                quarter_constraint,
                quarter_src,
            ) = state_queue.pop(0)
            print(
                prev_abs_state,
                dollar_delta,
                dollar_constraint,
                quarter_delta,
                quarter_constraint,
            )
            if time_delta is None:
                pass
            else:
                # advance the time stamp as required
                self._advance_timecounter(prev_state, time_delta)
            if dollar_delta is not None:
                self._advance_dollar(prev_state, dollar_delta)
            if quarter_delta is not None:
                self._advance_quarter(prev_state, quarter_delta)

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
                dollar_delta,
                quarter_delta,
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
                dollar_delta=dollar_delta,
                dollar_constraint=dollar_constraint,
                dollar_src=dollar_src,
                quarter_delta=quarter_delta,
                quarter_constraint=quarter_constraint,
                quarter_src=quarter_src,
                label=f"dollar={dollar_delta}, quarter={quarter_delta}",
            )

            # discover time deltas
            # also discover what other input fields are used in the constraints

            dollar_delta_and_sources = self._discover_dollar_deltas(next_state)
            if dollar_delta_and_sources:
                for delta, constraint, source in dollar_delta_and_sources:
                    if source is None:
                        block_addr, stmt_idx = -1, -1
                    else:
                        block_addr, stmt_idx = source
                    print(
                        f"[.] Discovered a new dollar {delta} defined at {block_addr:#x}:{stmt_idx}"
                    )
            else:
                dollar_delta_and_sources = [(None, None, None)]

            quarter_delta_and_sources = self._discover_quarter_deltas(next_state)
            if quarter_delta_and_sources:
                for delta, constraint, source in quarter_delta_and_sources:
                    if source is None:
                        block_addr, stmt_idx = -1, -1
                    else:
                        block_addr, stmt_idx = source
                    print(
                        f"[.] Discovered a new quarter {delta} defined at {block_addr:#x}:{stmt_idx}"
                    )
            else:
                quarter_delta_and_sources = [(None, None, None)]

            # add new work states with deltas to queue
            for (dollar_delta, dollar_constraint, dollar_src), (
                quarter_delta,
                quarter_constraint,
                quarter_src,
            ) in itertools.product(
                *[dollar_delta_and_sources, quarter_delta_and_sources]
            ):

                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(
                    new_state, self.fields
                )
                symbolic_time_counters = self._symbolize_timecounter(new_state)
                symbolic_dollar = self._symbolize_dollar(new_state)
                symbolic_quarter = self._symbolize_quarter(new_state)
                all_vars = set(symbolic_abstate_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                all_vars |= set(symbolic_dollar.values())
                all_vars |= set(symbolic_quarter.values())
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
                        dollar_delta,
                        dollar_constraint,
                        dollar_src,
                        quarter_delta,
                        quarter_constraint,
                        quarter_src,
                    )
                )

    def _discover_dollar_deltas(
        self, state: "SimState"
    ) -> List[Tuple[int, claripy.ast.Base, Tuple[int, int]]]:
        """
        Discover all possible dollar that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """
        if self.dollar is None:
            return []
        state = self._initialize_state(state)
        dollar_deltas = self._symbolically_advance_dollar(state)
        # setup inspection points to catch where comparison happens
        constraint_source = {}
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(
            when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints
        )
        state.inspect.add_breakpoint("constraints", bp_0)

        next_states = self._traverse_one(state, discover=True)
        # detect required dollar delta
        steps: List[Tuple[int, claripy.ast.Base, Tuple[int, int]]] = []
        for next_state in next_states:
            for delta in dollar_deltas:
                for constraint in next_state.solver.constraints:
                    original_constraint = constraint

                    if delta.args[0] in constraint.variables:
                        step = next_state.solver.eval(delta)

                        steps.append(
                            (
                                step,
                                constraint,
                                constraint_source.get(original_constraint, None),
                            )
                        )
                        continue

                    else:
                        continue
        print(steps)
        return steps

    def _discover_quarter_deltas(
        self, state: "SimState"
    ) -> List[Tuple[int, claripy.ast.Base, Tuple[int, int]]]:
        """
        Discover all possible high sensor that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """
        if self.quarter is None:
            return []
        state = self._initialize_state(state)
        quarter_deltas = self._symbolically_advance_quarter(state)
        # setup inspection points to catch where comparison happens
        constraint_source = {}
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(
            when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints
        )
        state.inspect.add_breakpoint("constraints", bp_0)

        next_states = self._traverse_one(state, discover=True)
        # detect required high delta
        steps: List[Tuple[int, claripy.ast.Base, Tuple[int, int]]] = []
        for next_state in next_states:
            for delta in quarter_deltas:
                for constraint in next_state.solver.constraints:
                    original_constraint = constraint

                    if delta.args[0] in constraint.variables:

                        step = next_state.solver.eval(delta)

                        steps.append(
                            (
                                step,
                                constraint,
                                constraint_source.get(original_constraint, None),
                            )
                        )
                        continue

                    else:
                        continue
        print(steps)
        return steps

    def _discover_dollar_and_quarter_deltas(self, state: "SimState"):
        """
        Discover all possible low and high sensor that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """
        state = self._initialize_state(state)
        dollar_delta = self._symbolically_advance_dollar(state)[0]
        quarter_delta = self._symbolically_advance_quarter(state)[0]
        # setup inspection points to catch where comparison happens
        constraint_source = {}
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(
            when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints
        )
        state.inspect.add_breakpoint("constraints", bp_0)

        next_states = self._traverse_one(state, discover=True)

        steps = []
        for next_state in next_states:
            dollar_steps = []
            quarter_steps = []
            for constraint in next_state.solver.constraints:
                if dollar_delta.args[0] in constraint.variables:
                    dollar_step = next_state.solver.eval(dollar_delta)
                    if dollar_step is not None:
                        dollar_steps.append(
                            (
                                dollar_step,
                                constraint,
                                constraint_source.get(constraint, None),
                            )
                        )
                if quarter_delta.args[0] in constraint.variables:
                    quarter_step = next_state.solver.eval(quarter_delta)
                    if quarter_step is not None:
                        quarter_steps.append(
                            (
                                quarter_step,
                                constraint,
                                constraint_source.get(constraint, None),
                            )
                        )
            if len(dollar_steps) > 1 or len(quarter_steps) > 1:
                # find multiple deltas in one state
                # TODO: if there are multiple deltas, we need to AND them as the final constraint
                raise NotImplementedError(
                    "multiple deltas in one state are not supported"
                )
            elif len(dollar_steps) == 0:
                dollar_steps.append((None, None, None))
            elif len(quarter_steps) == 0:
                quarter_steps.append((None, None, None))

            steps.append((dollar_steps[0], quarter_steps[0]))

        return steps

    def _symbolize_dollar(self, state: "SimState") -> Dict[str, claripy.ast.Base]:
        dollar_addr, dollar_sort, dollar_size = self.dollar_info
        prev = state.globals[dollar_addr]
        prev_dollar = state.solver.eval(prev)
        self.dollar = claripy.BVS("dollar", dollar_size * self.project.arch.byte_width)
        state.globals[dollar_addr] = self.dollar
        state.preconstrainer.preconstrain(
            claripy.BVV(prev_dollar, dollar_size * self.project.arch.byte_width),
            self.dollar,
        )
        return {"dollar": self.dollar}

    def _symbolically_advance_dollar(self, state: "SimState") -> List[claripy.ast.Bits]:
        dollar_addr, dollar_sort, dollar_size = self.dollar_info
        dollar_delta = claripy.BVS(
            "dollar_delta", dollar_size * self.project.arch.byte_width
        )
        state.globals[dollar_addr] = dollar_delta
        return [dollar_delta]

    def _advance_dollar(self, state: "SimState", delta) -> None:
        dollar_addr, dollar_sort, dollar_size = self.dollar_info
        self.dollar = claripy.BVS("dollar", dollar_size * self.project.arch.byte_width)
        state.globals[dollar_addr] = self.dollar
        state.preconstrainer.preconstrain(
            claripy.BVV(delta, dollar_size * self.project.arch.byte_width), self.dollar
        )

    def _symbolize_quarter(self, state: "SimState") -> Dict[str, claripy.ast.Base]:
        quarter_addr, quarter_sort, quarter_size = self.quarter_info
        self.quarter = claripy.BVS(
            "quarter", quarter_size * self.project.arch.byte_width
        )
        state.globals[quarter_addr] = self.quarter
        return {"quarter": self.quarter}

    def _symbolically_advance_quarter(
        self, state: "SimState"
    ) -> List[claripy.ast.Bits]:
        quarter_addr, quarter_sort, quarter_size = self.quarter_info
        quarter_delta = claripy.BVS(
            "quarter_delta", quarter_size * self.project.arch.byte_width
        )
        state.globals[quarter_addr] = quarter_delta
        return [quarter_delta]

    def _advance_quarter(self, state: "SimState", delta) -> None:
        quarter_addr, quarter_sort, quarter_size = self.quarter_info
        self.quarter = claripy.BVS(
            "quarter", quarter_size * self.project.arch.byte_width
        )
        state.globals[quarter_addr] = self.quarter
        state.preconstrainer.preconstrain(
            claripy.BVV(delta, quarter_size * self.project.arch.byte_width),
            self.quarter,
        )

    def _initialize_state(self, init_state=None) -> "SimState":
        if init_state is not None:
            s = init_state.copy()
            s.ip = self.func.addr
            s.globals[10] = 0
            s.globals[11] = 0
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
            s.stack_push(claripy.BVV(self._ret_trap, self.project.arch.bits))
        else:
            # set up the link register for the return address
            s.regs.lr = self._ret_trap

        return s


AnalysesHub.register_default(
    "StateGraphRecoveryVendingMachine", StateGraphRecoveryAnalysis
)
