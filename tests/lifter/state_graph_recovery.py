from itertools import count
from typing import Optional, List, Dict, Tuple, Set, Callable, Any, TYPE_CHECKING

from angr import claripy
import pprint
from angr.state_plugins.inspect import BP_BEFORE, BP
from angr.analyses.analysis import AnalysesHub
from angr.utils.timing import timethis
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
        self.current_rack_info = (
            inputs["CURRENT_RACK"] if inputs and "CURRENT_RACK" in inputs else None
        )
        self.current_rack = None
        self.extra_input_info = (
            inputs["extra_input"] if inputs and "extra_input" in inputs else None
        )
        self.extra_input = None
        self._tv_sec_var = None
        self._temperature = None
        self.state_graph = None
        self._expression_source = {}
        self.traverse_counter = 0
        self.traverse()

    def traverse(self):

        # create an empty state graph
        self.state_graph = MultiDiGraph_DedupeEdge()

        # make the initial state
        init_state = self._initialize_state(init_state=self.init_state)
        symbolic_abstate_fields = self._symbolize_var_fields(init_state, self.fields)
        symbolic_time_counters = self._symbolize_timecounter(init_state)
        if self.current_rack_info is not None:
            symbolic_current_rack = self._symbolize_current_rack(init_state)

        if self.extra_input_info is None:
            extra_input_delta = None

        # setup inspection points to catch where expressions are created
        all_vars = set(symbolic_abstate_fields.values())
        all_vars |= set(symbolic_time_counters.values())
        if self.current_rack_info is not None:
            all_vars | set(symbolic_current_rack.values())

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
                current_rack_delta,
                current_rack_constraint,
                current_rack_src,
            ) = state_queue.pop(0)
            print(
                prev_abs_state,
                current_rack_delta,
                current_rack_constraint,
                current_rack_src,
            )
            if time_delta is None:
                pass
            else:
                # advance the time stamp as required
                self._advance_timecounter(prev_state, time_delta)
            if current_rack_delta is not None:
                self._advance_current_rack(prev_state, current_rack_delta)
            if extra_input_delta is not None:
                self._advance_extra_input(prev_state, extra_input_delta)

            # symbolically trace the state
            intermediate_state = self._traverse_one(prev_state)
            print("finished round one")
            new_interm_state = self._initialize_state(init_state=intermediate_state)
            next_state = self._traverse_one(new_interm_state)
            print("finished round two")

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
                time_delta,
                current_rack_delta,
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
                current_rack_delta=current_rack_delta,
                current_rack_constraint=current_rack_constraint,
                current_rack_src=current_rack_src,
                label=f"time_delta={time_delta}\ncurrent_rack_delta={current_rack_delta}",
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

                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(
                    new_state, self.fields
                )
                symbolic_time_counters = self._symbolize_timecounter(new_state)
                if self.current_rack_info is not None:
                    symbolic_current_rack = self._symbolize_current_rack(new_state)
                all_vars = set(symbolic_abstate_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                if self.current_rack_info is not None:
                    all_vars |= set(symbolic_current_rack.values())
                all_vars |= self.config_vars
                state_queue.append(
                    (
                        new_state,
                        abs_state_id,
                        abs_state,
                        prev_abs_state,
                        delta,
                        constraint,
                        source,
                        None,
                        None,
                        None,
                    )
                )

            # add new work states with deltas to queue
            if self.current_rack_info is None:
                continue

            for (
                current_rack_delta,
                current_rack_constraint,
                current_rack_src,
            ) in self._discover_current_rack_deltas(next_state):
                if current_rack_src is None:
                    block_addr, stmt_idx = -1, -1
                else:
                    block_addr, stmt_idx = current_rack_src
                print(
                    f"[.] Discovered a new current rack delta {current_rack_delta} defined at {block_addr:#x}:{stmt_idx}"
                )

                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(
                    new_state, self.fields
                )
                symbolic_time_counters = self._symbolize_timecounter(new_state)
                symbolic_current_rack = self._symbolize_current_rack(new_state)
                all_vars = set(symbolic_abstate_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                all_vars |= set(symbolic_current_rack.values())
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
                        current_rack_delta,
                        current_rack_constraint,
                        current_rack_src,
                    )
                )

            if self.extra_input_info is None:
                continue
            for (
                extra_input_delta,
                extra_input_constraint,
                extra_input_src,
            ) in self._discover_extra_input_deltas(next_state):
                if extra_input_src is None:
                    block_addr, stmt_idx = -1, -1
                else:
                    block_addr, stmt_idx = extra_input_src
                print(
                    f"[.] Discovered a new extra input delta {extra_input_delta} defined at {block_addr:#x}:{stmt_idx}"
                )

                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(
                    new_state, self.fields
                )
                symbolic_time_counters = self._symbolize_timecounter(new_state)
                symbolic_current_rack = self._symbolize_current_rack(new_state)
                all_vars = set(symbolic_abstate_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                all_vars |= set(symbolic_current_rack.values())
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
                        None,
                        None,
                        None,
                        extra_input_delta,
                    )
                )

        print("traverse counter:", self.traverse_counter)

    def _discover_time_deltas(
        self, state: "SimState"
    ) -> List[Tuple[int, claripy.ast.Base, Tuple[int, int]]]:
        """
        Discover all possible time intervals that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """

        state = self._initialize_state(state)
        time_deltas = self._symbolically_advance_timecounter(state)
        # setup inspection points to catch where comparison happens
        constraint_source = {}
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(
            when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints
        )
        state.inspect.add_breakpoint("constraints", bp_0)

        next_state = self._traverse_one(state)
        # detect required time delta
        # TODO: Extend it to more than just seconds
        steps: List[Tuple[int, claripy.ast.Base, Tuple[int, int]]] = []
        if time_deltas:
            for delta in time_deltas:
                for constraint in next_state.solver.constraints:
                    original_constraint = constraint
                    # attempt simplification if this constraint has both config variables and time delta variables
                    if (
                        any(x.args[0] in constraint.variables for x in self.config_vars)
                        and delta.args[0] in constraint.variables
                    ):
                        simplified_constraint, self._expression_source = (
                            self._simplify_constraint(
                                constraint, self._expression_source
                            )
                        )
                        if simplified_constraint is not None:
                            constraint = simplified_constraint

                    if constraint.op == "__eq__" and constraint.args[0] is delta:
                        continue
                    elif constraint.op in ("ULE"):  # arduino arm32
                        if constraint.args[0].args[1] is delta:
                            if constraint.args[1].args[0].op == "BVV":
                                step = constraint.args[1].args[0].args[0]
                                if step != 0:
                                    steps.append(
                                        (
                                            step,
                                            constraint,
                                            constraint_source.get(
                                                original_constraint, None
                                            ),
                                        )
                                    )
                                    continue
                    elif constraint.op in ("__le__",):  # simulink arm32
                        if constraint.args[0].args[1] is delta:
                            if constraint.args[1].op == "BVV":
                                step = constraint.args[1].args[0]
                                if step != 0 and step < 255:
                                    steps.append(
                                        (
                                            step,
                                            constraint,
                                            constraint_source.get(
                                                original_constraint, None
                                            ),
                                        )
                                    )
                                    continue
                            elif (
                                constraint.args[1].args[0].op == "BVV"
                            ):  # arduino arm32 oven
                                step = constraint.args[1].args[0].args[0]
                                if step != 0:
                                    steps.append(
                                        (
                                            step,
                                            constraint,
                                            constraint_source.get(
                                                original_constraint, None
                                            ),
                                        )
                                    )
                                    continue
                    elif constraint.op == "__ne__":
                        if constraint.args[0] is delta:  # amd64
                            # found a potential step
                            if constraint.args[1].op == "BVV":
                                step = constraint.args[1].concrete_value
                                if step != 0 and step < 255:
                                    steps.append(
                                        (
                                            step,
                                            constraint,
                                            constraint_source.get(
                                                original_constraint, None
                                            ),
                                        )
                                    )
                                    continue
                            else:
                                # attempt to evaluate the right-hand side
                                values = state.solver.eval_upto(constraint.args[1], 2)
                                if len(values) == 1:
                                    # it has a single value!
                                    step = values[0]
                                    if step != 0:
                                        steps.append(
                                            (
                                                step,
                                                constraint,
                                                constraint_source.get(
                                                    original_constraint, None
                                                ),
                                            )
                                        )
                                        continue

                        if constraint.args[1].op == "BVS":  # arm32
                            # access constraint.args[1].args[2]
                            if (
                                constraint.args[1].args[2] is delta
                                or constraint.args[1] is delta
                            ):
                                if constraint.args[0].op == "BVV":
                                    step = constraint.args[0].args[0]
                                    if step != 0:
                                        steps.append(
                                            (
                                                step,
                                                constraint,
                                                constraint_source.get(
                                                    original_constraint, None
                                                ),
                                            )
                                        )
                                        continue
                        if (
                            constraint.args[0].op == "__add__"
                            and constraint.args[0].args[1] is delta
                        ):  # TON LE
                            if constraint.args[1].args[0].op == "BVV":
                                step = constraint.args[1].args[0].args[0]
                                if step != 0:
                                    steps.append(
                                        (
                                            step,
                                            constraint,
                                            constraint_source.get(
                                                original_constraint, None
                                            ),
                                        )
                                    )
                                    continue

        pprint.pprint(steps)
        return steps

    def _discover_current_rack_deltas(
        self, state: "SimState"
    ) -> List[Tuple[int, claripy.ast.Base, Tuple[int, int]]]:
        """
        Discover all possible water level that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """
        if self.current_rack is None:
            return []
        state = self._initialize_state(state)
        current_rack_deltas = self._symbolically_advance_current_rack(state)
        # setup inspection points to catch where comparison happens
        constraint_source = {}
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(
            when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints
        )
        state.inspect.add_breakpoint("constraints", bp_0)

        next_states = self._traverse_one(state, discover=True)

        # detect required delta
        steps: List[Tuple[int, claripy.ast.Base, Tuple[int, int]]] = []
        for next_state in next_states:
            for delta in current_rack_deltas:
                for constraint in next_state.solver.constraints:
                    original_constraint = constraint

                    if delta.args[0] in constraint.variables:
                        step = next_state.solver.min(delta)
                        if step != 1:

                            steps.append(
                                (
                                    step,
                                    constraint,
                                    constraint_source.get(original_constraint, None),
                                )
                            )
                        break

                    else:
                        continue
        pprint.pprint(steps)
        return steps

    def _discover_extra_input_deltas(
        self, state: "SimState"
    ) -> List[Tuple[int, claripy.ast.Base, Tuple[int, int]]]:
        if self.extra_input_info is None:
            return []
        state = self._initialize_state(state)
        extra_input_deltas = self._symbolically_advance_extra_input(state)
        # setup inspection points to catch where comparison happens
        constraint_source = {}
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(
            when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints
        )
        state.inspect.add_breakpoint("constraints", bp_0)

        next_states = self._traverse_one(state, discover=True)

        # detect required delta
        steps: List[Tuple[int, claripy.ast.Base, Tuple[int, int]]] = []
        for next_state in next_states:
            for delta in extra_input_deltas:
                for constraint in next_state.solver.constraints:
                    original_constraint = constraint

                    if delta.args[0] in constraint.variables:
                        step = next_state.solver.min(delta)

                        steps.append(
                            (
                                step,
                                constraint,
                                constraint_source.get(original_constraint, None),
                            )
                        )
                        break

                    else:
                        continue
        pprint.pprint(steps)
        return steps

    def _symbolize_current_rack(self, state: "SimState") -> Dict[str, claripy.ast.Base]:
        current_rack_addr, current_rack_sort, current_rack_size = self.current_rack_info
        prev = state.memory.load(
            current_rack_addr,
            size=current_rack_size,
            endness=self.project.arch.memory_endness,
        )
        prev_current_rack = state.solver.eval(prev)

        if current_rack_sort == "bool":
            self.current_rack = claripy.BVS(
                "current_rack", self.project.arch.byte_width
            )
            state.memory.store(
                current_rack_addr,
                self.current_rack,
                endness=self.project.arch.memory_endness,
            )
            state.preconstrainer.preconstrain(
                claripy.BVV(prev_current_rack, self.project.arch.byte_width),
                self.current_rack,
            )
            return {"current_rack": self.current_rack}
        elif current_rack_sort == "float":
            self.current_rack = claripy.FPS("current_rack", claripy.fp.FSORT_FLOAT)
            state.memory.store(
                current_rack_addr,
                self.current_rack,
                endness=self.project.arch.memory_endness,
            )
            state.preconstrainer.preconstrain(
                claripy.BVV(
                    prev_current_rack, current_rack_size * self.project.arch.byte_width
                ).raw_to_fp(),
                self.current_rack,
            )
            return {"current_rack": self.current_rack}
        else:
            self.current_rack = claripy.BVS(
                "current_rack", current_rack_size * self.project.arch.byte_width
            )
            state.memory.store(
                current_rack_addr,
                self.current_rack,
                endness=self.project.arch.memory_endness,
            )
            state.preconstrainer.preconstrain(
                claripy.BVV(
                    prev_current_rack, current_rack_size * self.project.arch.byte_width
                ),
                self.current_rack,
            )
            return {"current_rack": self.current_rack}

    def _symbolically_advance_current_rack(
        self, state: "SimState"
    ) -> List[claripy.ast.Bits]:
        current_rack_addr, current_rack_sort, current_rack_size = self.current_rack_info
        if current_rack_sort == "bool":
            current_rack_delta = claripy.BVS(
                "current_rack_delta", self.project.arch.byte_width
            )
        elif current_rack_sort == "float":
            current_rack_delta = claripy.FPS(
                "current_rack_delta", claripy.fp.FSORT_FLOAT
            )
        else:
            current_rack_delta = claripy.BVS(
                "current_rack_delta", current_rack_size * self.project.arch.byte_width
            )
        state.memory.store(
            current_rack_addr,
            current_rack_delta,
            endness=self.project.arch.memory_endness,
        )
        return [current_rack_delta]

    def _advance_current_rack(self, state: "SimState", delta) -> None:
        current_rack_addr, current_rack_sort, current_rack_size = self.current_rack_info

        if current_rack_sort == "bool":
            self.current_rack = claripy.BVS(
                "current_rack", self.project.arch.byte_width
            )
            state.memory.store(
                current_rack_addr,
                self.current_rack,
                endness=self.project.arch.memory_endness,
            )
            state.preconstrainer.preconstrain(
                claripy.BVV(delta, self.project.arch.byte_width), self.current_rack
            )

        elif current_rack_sort == "float":
            self.current_rack = claripy.FPS("current_rack", claripy.fp.FSORT_FLOAT)
            state.memory.store(
                current_rack_addr,
                self.current_rack,
                endness=self.project.arch.memory_endness,
            )
            state.preconstrainer.preconstrain(
                claripy.FPV(delta, claripy.fp.FSORT_FLOAT), self.current_rack
            )
        else:
            self.current_rack = claripy.BVS(
                "current_rack", current_rack_size * self.project.arch.byte_width
            )
            state.memory.store(
                current_rack_addr,
                self.current_rack,
                endness=self.project.arch.memory_endness,
            )
            state.preconstrainer.preconstrain(
                claripy.BVV(delta, current_rack_size * self.project.arch.byte_width),
                self.current_rack,
            )

    def _symbolically_advance_extra_input(
        self, state: "SimState"
    ) -> List[claripy.ast.Bits]:
        extra_input_addr, extra_input_sort, extra_input_size = self.extra_input_info
        if extra_input_sort == "bool":
            extra_input_delta = claripy.BVS(
                "extra_input_delta", self.project.arch.byte_width
            )
        elif extra_input_sort == "float":
            extra_input_delta = claripy.FPS("extra_input_delta", claripy.fp.FSORT_FLOAT)
        else:
            extra_input_delta = claripy.BVS(
                "extra_input_delta", extra_input_size * self.project.arch.byte_width
            )
        state.memory.store(
            extra_input_addr,
            extra_input_delta,
            endness=self.project.arch.memory_endness,
        )
        return [extra_input_delta]

    def _advance_extra_input(self, state: "SimState", delta) -> None:
        extra_input_addr, extra_input_sort, extra_input_size = self.extra_input_info

        if extra_input_sort == "bool":
            self.extra_input = claripy.BVS("extra_input", self.project.arch.byte_width)
            state.memory.store(
                extra_input_addr,
                self.extra_input,
                endness=self.project.arch.memory_endness,
            )
            state.preconstrainer.preconstrain(
                claripy.BVV(delta, self.project.arch.byte_width), self.extra_input
            )

        elif extra_input_sort == "float":
            self.extra_input = claripy.FPS("extra_input", claripy.fp.FSORT_FLOAT)
            state.memory.store(
                extra_input_addr,
                self.extra_input,
                endness=self.project.arch.memory_endness,
            )
            state.preconstrainer.preconstrain(
                claripy.FPV(delta, claripy.fp.FSORT_FLOAT), self.extra_input
            )
        else:
            self.extra_input = claripy.BVS(
                "extra_input", extra_input_size * self.project.arch.byte_width
            )
            state.memory.store(
                extra_input_addr,
                self.extra_input,
                endness=self.project.arch.memory_endness,
            )
            state.preconstrainer.preconstrain(
                claripy.BVV(delta, extra_input_size * self.project.arch.byte_width),
                self.extra_input,
            )

    @timethis
    def _traverse_one(self, state: "SimState", discover: bool = False):
        self.traverse_counter += 1
        simgr = self.project.factory.simgr(state)

        while simgr.active:
            s = simgr.active[0]
            if not discover:
                if len(simgr.active) > 1:
                    raise RuntimeError(
                        "scan cycle execution forked into multiple active states"
                    )

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


AnalysesHub.register_default("StateGraphRecoveryLifter", StateGraphRecoveryAnalysis)
