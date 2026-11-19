from itertools import count
from typing import Optional, List, Dict, Tuple, Set, Callable, Any, TYPE_CHECKING

import networkx
import pprint
from angr import claripy

from angr.sim_options import (
    NO_CROSS_INSN_OPT,
    SYMBOL_FILL_UNCONSTRAINED_MEMORY,
    SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
)
from angr.state_plugins.inspect import BP_BEFORE, BP_AFTER, BP
from angr.analyses.analysis import AnalysesHub
from taveren.state_graph_recovery import (
    ConstraintLogger,
    DefinitionNode,
    StateGraphRecoveryBase,
)

if TYPE_CHECKING:
    from angr import SimState
    from angr.knowledge_plugins.functions import Function
    from .abstract_state import AbstractStateFields


class SliceGenerator:
    def __init__(self, symbolic_exprs: Set[claripy.ast.Base], bp: Optional[BP] = None):
        self.bp: Optional[BP] = bp
        self.symbolic_exprs = symbolic_exprs
        self.expr_variables = set()

        # FIXME: The algorithm is hackish and incorrect. We should fix it later.
        self._last_statements = {}
        self.slice = networkx.DiGraph()

        for expr in self.symbolic_exprs:
            self.expr_variables |= expr.variables

        if self.bp is not None:
            self.bp.action = self._examine_expr

    def install_expr_hook(self, state: "SimState") -> BP:
        bp = BP(when=BP_AFTER, enabled=False, action=self._examine_expr)
        state.inspect.add_breakpoint("expr", bp)
        self.bp = bp
        return bp

    def _examine_expr(self, state: "SimState"):
        expr = state._inspect_getattr("expr_result", None)
        if state.solver.symbolic(expr) and expr.variables.intersection(
            self.expr_variables
        ):

            variables = expr.variables
            curr_loc = state.scratch.irsb.addr, state.scratch.stmt_idx
            for v in variables:
                pred = self._last_statements.get(v, None)
                if pred is not None:
                    self.slice.add_edge(
                        DefinitionNode(v, pred[0], pred[1]),
                        DefinitionNode(v, curr_loc[0], curr_loc[1]),
                    )
                self._last_statements[v] = curr_loc


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
        self._ret_trap: int = 0x1F37FF4C
        self.printstate = printstate
        self.patch_callback = patch_callback

        self._time_addr = time_addr
        self.product_sensor_info = inputs["PRODUCT_SENSOR"]
        self.product_empty_sensor_info = inputs["PRODUCT_EMPTY_SENSOR"]
        self.product_sensor = None
        self.product_empty_sensor = None
        self._tv_sec_var = None
        self._temperature = None
        self.state_graph = None
        self._expression_source = {}
        self.traverse()

    def traverse(self):

        # create an empty state graph
        self.state_graph = networkx.DiGraph()

        # make the initial state
        init_state = self._initialize_state(init_state=self.init_state)
        symbolic_abstate_fields = self._symbolize_var_fields(init_state, self.fields)
        symbolic_time_counters = self._symbolize_timecounter(init_state)
        symbolic_product_sensor = self._symbolize_product_sensor(init_state)
        symbolic_product_empty_sensor = self._symbolize_product_empty_sensor(init_state)

        # setup inspection points to catch where expressions are created
        all_vars = set(symbolic_abstate_fields.values())
        all_vars |= set(symbolic_time_counters.values())
        all_vars | set(symbolic_product_sensor.values())
        all_vars | set(symbolic_product_empty_sensor.values())

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

        if self._switch_on:
            countdown_timer = 1
            switched_on = False

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
                product_delta,
                product_constraint,
                product_src,
                product_empty_delta,
                product_empty_constraint,
                product_empty_src,
            ) = state_queue.pop(0)
            print(
                prev_abs_state,
                product_delta,
                product_constraint,
                product_empty_delta,
                product_empty_constraint,
            )
            if time_delta is None:
                pass
            else:
                # advance the time stamp as required
                self._advance_timecounter(prev_state, time_delta)
            if product_delta is not None:
                self._advance_product_sensor(prev_state, product_delta)
            if product_empty_delta is not None:
                self._advance_product_empty_sensor(prev_state, product_empty_delta)

            # symbolically trace the state
            next_state = self._traverse_one(prev_state)
            print(
                "current time",
                next_state.solver.eval(
                    next_state.memory.load(
                        self._time_addr, 8, endness=self.project.arch.memory_endness
                    )
                ),
            )

            abs_state = self.fields.generate_abstract_state(next_state)

            abs_state += (("time_delta", time_delta),)
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
                product_delta,
                product_empty_delta,
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
                product_delta=product_delta,
                product_constraint=product_constraint,
                product_src=product_src,
                product_empty_delta=product_empty_delta,
                product_empty_constraint=product_empty_constraint,
                product_empty_src=product_empty_src,
                label=f"time={time_delta}, product={product_delta}, product_empty={product_empty_delta}",
            )

            if not switched_on and self._switch_on is not None:
                if countdown_timer > 0:
                    print("[.] Pre-heat... %d" % countdown_timer)
                    countdown_timer -= 1
                    new_state = self._initialize_state(init_state=next_state)
                    state_queue.append(
                        (
                            new_state,
                            abs_state_id,
                            abs_state,
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
                    continue
                else:
                    print("[.] Switch on.")
                    self._switch_on(next_state)
                    switched_on = True
                    prev_abs_state = None
                    new_state = self._initialize_state(init_state=next_state)
                    state_queue.append(
                        (
                            new_state,
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
                    )
            else:
                # discover time deltas
                # also discover what other input fields are used in the constraints
                time_delta_and_sources = self._discover_time_deltas(next_state)

                for time_delta, time_constraint, time_source in time_delta_and_sources:
                    if time_source is None:
                        block_addr, stmt_idx = -1, -1
                    else:
                        block_addr, stmt_idx = time_source
                    print(
                        f"[.] Discovered a new time interval {time_delta} defined at {block_addr:#x}:{stmt_idx}"
                    )

                    # append state satisfy constraint
                    new_state = self._initialize_state(init_state=next_state)

                    # re-symbolize input fields, time counters, and update slice generator
                    symbolic_abstate_fields = self._symbolize_var_fields(
                        new_state, self.fields
                    )
                    symbolic_time_counters = self._symbolize_timecounter(new_state)
                    symbolic_product_sensor = self._symbolize_product_sensor(new_state)
                    symbolic_product_empty_sensor = (
                        self._symbolize_product_empty_sensor(new_state)
                    )
                    all_vars = set(symbolic_abstate_fields.values())
                    all_vars |= set(symbolic_time_counters.values())
                    all_vars |= set(symbolic_product_sensor.values())
                    all_vars |= set(symbolic_product_empty_sensor.values())
                    all_vars |= self.config_vars
                    # FIXME: this is a hack, product time with other deltas
                    state_queue.append(
                        (
                            new_state,
                            abs_state_id,
                            abs_state,
                            prev_abs_state,
                            time_delta,
                            time_constraint,
                            time_source,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                        )
                    )

                # add new work states with deltas to queue
                for (product_delta, product_constraint, product_src), (
                    product_empty_delta,
                    product_empty_constraint,
                    product_empty_src,
                ) in self._discover_product_and_product_empty_deltas(next_state):
                    new_state = self._initialize_state(init_state=next_state)

                    # re-symbolize input fields, time counters, and update slice generator
                    symbolic_abstate_fields = self._symbolize_var_fields(
                        new_state, self.fields
                    )
                    symbolic_time_counters = self._symbolize_timecounter(new_state)
                    symbolic_product_sensor = self._symbolize_product_sensor(new_state)
                    symbolic_product_empty_sensor = (
                        self._symbolize_product_empty_sensor(new_state)
                    )
                    all_vars = set(symbolic_abstate_fields.values())
                    all_vars |= set(symbolic_time_counters.values())
                    all_vars |= set(symbolic_product_sensor.values())
                    all_vars |= set(symbolic_product_empty_sensor.values())
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
                            product_delta,
                            product_constraint,
                            product_src,
                            product_empty_delta,
                            product_empty_constraint,
                            product_empty_src,
                        )
                    )

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
        return steps

    def _discover_product_deltas(
        self, state: "SimState"
    ) -> List[Tuple[int, claripy.ast.Base, Tuple[int, int]]]:
        """
        Discover all possible product sensor that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """
        if self.product_sensor is None:
            return []
        state = self._initialize_state(state)
        product_deltas = self._symbolically_advance_product_sensor(state)
        # setup inspection points to catch where comparison happens
        constraint_source = {}
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(
            when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints
        )
        state.inspect.add_breakpoint("constraints", bp_0)

        next_states = self._traverse_one(state, discover=True)
        # detect required product delta
        steps: List[Tuple[int, claripy.ast.Base, Tuple[int, int]]] = []
        for next_state in next_states:
            for delta in product_deltas:
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

        return steps

    def _discover_product_empty_deltas(
        self, state: "SimState"
    ) -> List[Tuple[int, claripy.ast.Base, Tuple[int, int]]]:
        """
        Discover all possible product_empty sensor that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """
        if self.product_empty_sensor is None:
            return []
        state = self._initialize_state(state)
        product_empty_deltas = self._symbolically_advance_product_empty_sensor(state)
        # setup inspection points to catch where comparison happens
        constraint_source = {}
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(
            when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints
        )
        state.inspect.add_breakpoint("constraints", bp_0)

        next_states = self._traverse_one(state, discover=True)
        # detect required product_empty delta
        steps: List[Tuple[int, claripy.ast.Base, Tuple[int, int]]] = []
        for next_state in next_states:
            for delta in product_empty_deltas:
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

        return steps

    def _discover_product_and_product_empty_deltas(self, state: "SimState"):
        """
        Discover all possible product and product_empty sensor that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """
        state = self._initialize_state(state)
        product_delta = self._symbolically_advance_product_sensor(state)[0]
        product_empty_delta = self._symbolically_advance_product_empty_sensor(state)[0]
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
            product_steps = []
            product_empty_steps = []
            for constraint in next_state.solver.constraints:
                if product_delta.args[0] in constraint.variables:
                    product_step = next_state.solver.eval(product_delta)
                    if product_step is not None:
                        product_steps.append(
                            (
                                product_step,
                                constraint,
                                constraint_source.get(constraint, None),
                            )
                        )
                if product_empty_delta.args[0] in constraint.variables:
                    product_empty_step = next_state.solver.eval(product_empty_delta)
                    if product_empty_step is not None:
                        product_empty_steps.append(
                            (
                                product_empty_step,
                                constraint,
                                constraint_source.get(constraint, None),
                            )
                        )
            if len(product_steps) > 1 or len(product_empty_steps) > 1:
                # find multiple deltas in one state
                # TODO: if there are multiple deltas, we need to AND them as the final constraint
                raise NotImplementedError(
                    "multiple deltas in one state are not supported"
                )
            if len(product_steps) == 0:
                product_steps.append((None, None, None))
            if len(product_empty_steps) == 0:
                product_empty_steps.append((None, None, None))
            steps.append((product_steps[0], product_empty_steps[0]))

        return steps

    def _symbolize_product_sensor(
        self, state: "SimState"
    ) -> Dict[str, claripy.ast.Base]:
        product_sensor_addr, product_sensor_sort, product_sensor_size = (
            self.product_sensor_info
        )
        prev = state.memory.load(
            product_sensor_addr,
            size=product_sensor_size,
            endness=self.project.arch.memory_endness,
        )
        prev_product_sensor = state.solver.eval(prev)
        self.product_sensor = claripy.BVS(
            "product_sensor", product_sensor_size * self.project.arch.byte_width
        )
        state.memory.store(
            product_sensor_addr,
            self.product_sensor,
            endness=self.project.arch.memory_endness,
        )
        state.preconstrainer.preconstrain(
            claripy.BVV(
                prev_product_sensor, product_sensor_size * self.project.arch.byte_width
            ),
            self.product_sensor,
        )
        return {"product_sensor": self.product_sensor}

    def _symbolically_advance_product_sensor(
        self, state: "SimState"
    ) -> List[claripy.ast.Bits]:
        product_sensor_addr, product_sensor_sort, product_sensor_size = (
            self.product_sensor_info
        )
        product_delta = claripy.BVS(
            "product_delta", product_sensor_size * self.project.arch.byte_width
        )
        state.memory.store(
            product_sensor_addr, product_delta, endness=self.project.arch.memory_endness
        )
        return [product_delta]

    def _advance_product_sensor(self, state: "SimState", delta) -> None:
        product_sensor_addr, product_sensor_sort, product_sensor_size = (
            self.product_sensor_info
        )
        self.product_sensor = claripy.BVS(
            "product_sensor", product_sensor_size * self.project.arch.byte_width
        )
        state.memory.store(
            product_sensor_addr,
            self.product_sensor,
            endness=self.project.arch.memory_endness,
        )
        state.preconstrainer.preconstrain(
            claripy.BVV(delta, product_sensor_size * self.project.arch.byte_width),
            self.product_sensor,
        )

    def _symbolize_product_empty_sensor(
        self, state: "SimState"
    ) -> Dict[str, claripy.ast.Base]:
        (
            product_empty_sensor_addr,
            product_empty_sensor_sort,
            product_empty_sensor_size,
        ) = self.product_empty_sensor_info
        prev = state.memory.load(
            product_empty_sensor_addr,
            size=product_empty_sensor_size,
            endness=self.project.arch.memory_endness,
        )
        prev_product_empty_sensor = state.solver.eval(prev)
        self.product_empty_sensor = claripy.BVS(
            "product_empty_sensor",
            product_empty_sensor_size * self.project.arch.byte_width,
        )
        state.memory.store(
            product_empty_sensor_addr,
            self.product_empty_sensor,
            endness=self.project.arch.memory_endness,
        )
        state.preconstrainer.preconstrain(
            claripy.BVV(
                prev_product_empty_sensor,
                product_empty_sensor_size * self.project.arch.byte_width,
            ),
            self.product_empty_sensor,
        )
        return {"product_empty_sensor": self.product_empty_sensor}

    def _symbolically_advance_product_empty_sensor(
        self, state: "SimState"
    ) -> List[claripy.ast.Bits]:
        (
            product_empty_sensor_addr,
            product_empty_sensor_sort,
            product_empty_sensor_size,
        ) = self.product_empty_sensor_info
        product_empty_delta = claripy.BVS(
            "product_empty_delta",
            product_empty_sensor_size * self.project.arch.byte_width,
        )
        state.memory.store(
            product_empty_sensor_addr,
            product_empty_delta,
            endness=self.project.arch.memory_endness,
        )
        return [product_empty_delta]

    def _advance_product_empty_sensor(self, state: "SimState", delta) -> None:
        (
            product_empty_sensor_addr,
            product_empty_sensor_sort,
            product_empty_sensor_size,
        ) = self.product_empty_sensor_info
        self.product_empty_sensor = claripy.BVS(
            "product_empty_sensor",
            product_empty_sensor_size * self.project.arch.byte_width,
        )
        state.memory.store(
            product_empty_sensor_addr,
            self.product_empty_sensor,
            endness=self.project.arch.memory_endness,
        )
        state.preconstrainer.preconstrain(
            claripy.BVV(
                delta, product_empty_sensor_size * self.project.arch.byte_width
            ),
            self.product_empty_sensor,
        )

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
        s.options[NO_CROSS_INSN_OPT] = False
        # disable warnings
        s.options[SYMBOL_FILL_UNCONSTRAINED_MEMORY] = True
        s.options[SYMBOL_FILL_UNCONSTRAINED_REGISTERS] = True

        if self.project.arch.call_pushes_ret:
            s.stack_push(claripy.BVV(self._ret_trap, self.project.arch.bits))
        elif "mips" in self.project.arch.name.lower():
            s.regs.ra = self._ret_trap
            s.regs.t9 = self.func.addr
        elif "ppc" in self.project.arch.name.lower():
            s.regs.lr = self._ret_trap
            s.regs.gpr12 = self.func.addr
        else:
            # set up the link register for the return address
            s.regs.lr = self._ret_trap

        return s


AnalysesHub.register_default("StateGraphRecoveryPackaging", StateGraphRecoveryAnalysis)
