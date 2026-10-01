from itertools import count
from typing import Optional, List, Dict, Tuple, Set, Callable, Any, TYPE_CHECKING

import claripy
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
        # self.state_graph = networkx.DiGraph()

        # make the initial state
        init_state = self._initialize_state(init_state=self.init_state)
        symbolic_abstate_fields = self._symbolize_var_fields(init_state, self.fields)
        # symbolic_input_fields = self._symbolize_var_fields(init_state, self.fields_input)
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
        # if self.extra_input_info is not None:
        #     symbolic_extra_input = self._symbolize_extra_input(init_state)
        #     all_vars |= set(symbolic_extra_input.values())
        # slice_gen = SliceGenerator(all_vars, bp=None)
        # expression_bp = slice_gen.install_expr_hook(init_state)

        # # setup inspection points to catch where expressions are written to registers
        # expression_logger = ExpressionLogger(self._expression_source, { v.args[0] for v in all_vars })
        # regwrite_bp = BP(when=BP_BEFORE, enabled=True, action=expression_logger.on_register_write)
        # init_state.inspect.add_breakpoint('reg_write', regwrite_bp)
        # memread_bp = BP(when=BP_AFTER, enabled=True, action=expression_logger.on_memory_read)
        # init_state.inspect.add_breakpoint('mem_read', memread_bp)

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
        """
        if self._switch_on is None:
            countdown_timer = 0
            switched_on = True
            time_delta_and_sources = self._discover_time_deltas(init_state)

            for delta, constraint, source in time_delta_and_sources:
                if source is None:
                    block_addr, stmt_idx = -1, -1
                else:
                    block_addr, stmt_idx = source
                print(f"[.] Discovered a new time interval {delta} defined at {block_addr:#x}:{stmt_idx}")
            if self._temp_addr is not None:
                temp_delta_and_sources = self._discover_temp_deltas(init_state)
                for delta, constraint, source in temp_delta_and_sources:
                    if source is None:
                        block_addr, stmt_idx = -1, -1
                    else:
                        block_addr, stmt_idx = source
                    print(f"[.] Discovered a new temperature {delta} defined at {block_addr:#x}:{stmt_idx}")

            if temp_delta_and_sources or time_delta_and_sources:

                if temp_delta_and_sources:

                    for temp_delta, temp_constraint, temp_src in temp_delta_and_sources:
                        # append two states in queue
                        op = temp_constraint.args[0].op
                        prev = init_state.memory.load(self._temp_addr, 8,
                                                      endness=self.project.arch.memory_endness).raw_to_fp()
                        prev_temp = init_state.solver.eval(prev)
                        if op in ['fpLEQ', 'fpLT', 'fpGEQ', 'fpGT']:
                            if prev_temp < temp_delta:
                                delta0, temp_constraint0, temp_src0 = None, None, None
                                delta1, temp_constraint1, temp_src1 = temp_delta + 1.0, temp_constraint, temp_src

                                new_state = self._initialize_state(init_state=init_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_abstate_fields = self._symbolize_var_fields(new_state)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_abstate_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append(
                                    (new_state, abs_state_id, abs_state, None, None, None, None, delta1,
                                     temp_constraint1, temp_src1))
                            elif prev_temp > temp_delta:
                                delta0, temp_constraint0, temp_src0 = temp_delta - 1.0, temp_constraint, temp_src
                                delta1, temp_constraint1, temp_src1 = None, None, None

                                new_state = self._initialize_state(init_state=init_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_abstate_fields = self._symbolize_var_fields(new_state)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_abstate_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append(
                                    (new_state, abs_state_id, abs_state, None, None, None, None, delta0,
                                     temp_constraint0, temp_src0))
                            else:
                                raise RuntimeError(f"temperature delta {temp_delta} equals the previous temperature")

                        elif op in ['fpEQ']:
                            new_state = self._initialize_state(init_state=init_state)

                            # re-symbolize input fields, time counters, and update slice generator
                            symbolic_abstate_fields = self._symbolize_var_fields(new_state)
                            symbolic_time_counters = self._symbolize_timecounter(new_state)
                            symbolic_temperature = self._symbolize_temp(new_state)
                            all_vars = set(symbolic_abstate_fields.values())
                            all_vars |= set(symbolic_time_counters.values())
                            all_vars |= set(symbolic_temperature.values())
                            all_vars |= self.config_vars
                            slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                            state_queue.append((new_state, abs_state_id, abs_state, None, None, None, None,
                                                temp_delta, temp_constraint, temp_src))
                            continue

                        if time_delta_and_sources:
                            # print(time_delta_constraint)
                            for time_delta, time_constraint, time_src in time_delta_and_sources:
                                # append state satisfy constraint
                                new_state = self._initialize_state(init_state=init_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_abstate_fields = self._symbolize_var_fields(new_state)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_abstate_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append((new_state, abs_state_id, abs_state, None, time_delta,
                                                    time_constraint, time_src, delta0, temp_constraint0, temp_src0))

                                # append state not satisfy constraint
                                new_state = self._initialize_state(init_state=init_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_abstate_fields = self._symbolize_var_fields(new_state)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_abstate_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append((new_state, abs_state_id, abs_state, None, time_delta,
                                                    time_constraint, time_src, delta1, temp_constraint1, temp_src1))

                # only discover time delta
                else:
                    for time_delta, time_constraint, time_src in time_delta_and_sources:
                        new_state = self._initialize_state(init_state=init_state)

                        # re-symbolize input fields, time counters, and update slice generator
                        symbolic_abstate_fields = self._symbolize_var_fields(new_state)
                        symbolic_time_counters = self._symbolize_timecounter(new_state)
                        all_vars = set(symbolic_abstate_fields.values())
                        all_vars |= set(symbolic_time_counters.values())
                        if self._temp_addr is not None:
                            symbolic_temperature = self._symbolize_temp(new_state)
                            all_vars |= set(symbolic_temperature.values())
                        all_vars |= self.config_vars
                        slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                        state_queue.append((new_state, abs_state_id, abs_state, None, time_delta, time_constraint,
                                            time_src, None, None, None))

            else:
                # if time_delta is None and prev_abs_state == abs_state:
                #     continue
                new_state = self._initialize_state(init_state=init_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(new_state)
                symbolic_time_counters = self._symbolize_timecounter(new_state)

                all_vars = set(symbolic_abstate_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                if self._temp_addr is not None:
                    symbolic_temperature = self._symbolize_temp(new_state)
                    all_vars |= set(symbolic_temperature.values())
                all_vars |= self.config_vars
                slice_gen = SliceGenerator(all_vars, bp=expression_bp)

                state_queue.append((new_state, abs_state_id, abs_state, None, None, None, None, None, None, None))
        else:
            countdown_timer = 2  # how many iterations to execute before switching on
            switched_on = False
        """
        known_transitions = list()
        known_states = dict()
        absstate_to_slice = {}
        while state_queue:
            # prev_state, prev_abs_state_id, prev_abs_state, prev_prev_abs, time_delta, time_delta_constraint, time_delta_src, current_rack_delta, current_rack_constraint, current_rack_src, extra_input_delta = state_queue.pop(0)     # test extra input
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
            # if prev_abs_state[0][1] == 1 and low_delta == 0:
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
            # expression_bp.enabled = True
            intermediate_state = self._traverse_one(prev_state)
            print("finished round one")
            new_interm_state = self._initialize_state(init_state=intermediate_state)
            next_state = self._traverse_one(new_interm_state)
            print("finished round two")
            # print(next_state.solver.eval(next_state.memory.load(self._time_addr, 8, endness=self.project.arch.memory_endness)))

            # expression_bp.enabled = False

            abs_state = self.fields.generate_abstract_state(next_state)

            # abs_state += (('time_delta', time_delta),
            #               # ('tdc', time_delta_constraint),
            #               # ('td_src', time_delta_src),
            #               #   ('low_delta', low_delta),
            #               #   ('low_constraint', low_constraint),
            #               #   ('low_src', low_src),
            #               #   ('high_delta', high_delta),
            #               #   ('high_constraint', high_constraint),
            #               #   ('high_src', high_src),
            #               )
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
            # absstate_to_slice[abs_state] = slice_gen.slice
            # print("[.] There are %d nodes in the slice." % len(slice_gen.slice))

            transition = (
                prev_prev_abs,
                prev_abs_state,
                abs_state,
                time_delta,
                current_rack_delta,
            )
            # print(transition)
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
                # extra_input_delta=extra_input_delta,
                # label = f'time_delta_constraint={time_delta_constraint},\nlow_constraint={low_constraint}, \nhigh_constraint={high_constraint}'
                # label = f"time_delta={time_delta}\ncurrent_rack_delta={current_rack_delta}\nextra_input={extra_input_delta}"
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
                # slice_gen = SliceGenerator(all_vars, bp=expression_bp)
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

            # low_delta_and_sources = self._discover_low_deltas(next_state)
            # for delta, constraint, source in low_delta_and_sources:
            #     if source is None:
            #         block_addr, stmt_idx = -1, -1
            #     else:
            #         block_addr, stmt_idx = source
            #     print(f"[.] Discovered a new low sensor {delta} defined at {block_addr:#x}:{stmt_idx}")
            #
            # high_delta_and_sources = self._discover_high_deltas(next_state)
            # if high_delta_and_sources:
            #     for delta, constraint, source in high_delta_and_sources:
            #         if source is None:
            #             block_addr, stmt_idx = -1, -1
            #         else:
            #             block_addr, stmt_idx = source
            #         print(f"[.] Discovered a new high sensor {delta} defined at {block_addr:#x}:{stmt_idx}")
            # else:
            #     high_delta_and_sources = [(None, None, None)]

            # FIXME: This is a hack. We should fix it later.
            # low_delta_and_sources = [(0, None, None), (1, None, None)]
            # high_delta_and_sources = [(0, None, None), (1, None, None)]

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
                # slice_gen = SliceGenerator(all_vars, bp=expression_bp)
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
                # slice_gen = SliceGenerator(all_vars, bp=expression_bp)
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
        """

            if temp_delta_and_sources or time_delta_and_sources:

                if temp_delta_and_sources:

                    for temp_delta, temp_constraint, temp_src in temp_delta_and_sources:
                        # append two states in queue
                        op = temp_constraint.args[0].op
                        prev = next_state.memory.load(self._temp_addr, 8, endness=self.project.arch.memory_endness).raw_to_fp()
                        prev_temp = next_state.solver.eval(prev)
                        if op in ['fpLEQ', 'fpLT', 'fpGEQ', 'fpGT']:
                            if prev_temp < temp_delta:
                                delta0, temp_constraint0, temp_src0 = None, None, None
                                delta1, temp_constraint1, temp_src1 = temp_delta + 1.0, temp_constraint, temp_src

                                new_state = self._initialize_state(init_state=next_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_abstate_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, delta1,
                                                    temp_constraint1, temp_src1))
                            elif prev_temp > temp_delta:
                                delta0, temp_constraint0, temp_src0 = temp_delta - 1.0, temp_constraint, temp_src
                                delta1, temp_constraint1, temp_src1 = None, None, None

                                new_state = self._initialize_state(init_state=next_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_abstate_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, delta0,
                                                    temp_constraint0, temp_src0))
                            else:
                                raise RuntimeError(f"temperature delta {temp_delta} equals the previous temperature")

                        elif op in ['fpEQ']:
                            new_state = self._initialize_state(init_state=next_state)

                            # re-symbolize input fields, time counters, and update slice generator
                            symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                            symbolic_time_counters = self._symbolize_timecounter(new_state)
                            symbolic_temperature = self._symbolize_temp(new_state)
                            all_vars = set(symbolic_abstate_fields.values())
                            all_vars |= set(symbolic_time_counters.values())
                            all_vars |= set(symbolic_temperature.values())
                            all_vars |= self.config_vars
                            slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                            state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, temp_delta, temp_constraint, temp_src))
                            continue

                        if time_delta_and_sources:
                            # print(time_delta_constraint)
                            for time_delta, time_constraint, time_src in time_delta_and_sources:
                                # append state satisfy constraint
                                new_state = self._initialize_state(init_state=next_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_abstate_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, time_delta, time_constraint, time_src, delta0, temp_constraint0, temp_src0))

                                # append state not satisfy constraint
                                new_state = self._initialize_state(init_state=next_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_abstate_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, time_delta, time_constraint, time_src, delta1, temp_constraint1, temp_src1))

                # only discover time delta
                else:
                    for time_delta, time_constraint, time_src in time_delta_and_sources:
                        new_state = self._initialize_state(init_state=next_state)

                        # re-symbolize input fields, time counters, and update slice generator
                        symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                        symbolic_time_counters = self._symbolize_timecounter(new_state)
                        all_vars = set(symbolic_abstate_fields.values())
                        all_vars |= set(symbolic_time_counters.values())
                        if self._temp_addr is not None:
                            symbolic_temperature = self._symbolize_temp(new_state)
                            all_vars |= set(symbolic_temperature.values())
                        all_vars |= self.config_vars
                        slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                        state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, time_delta, time_constraint, time_src, None, None, None))

            else:
            # if time_delta is None and prev_abs_state == abs_state:
            #     continue
            # if self._temp_addr:
                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                symbolic_time_counters = self._symbolize_timecounter(new_state)

                all_vars = set(symbolic_abstate_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                if self._temp_addr is not None:
                    symbolic_temperature = self._symbolize_temp(new_state)
                    all_vars |= set(symbolic_temperature.values())
                all_vars |= self.config_vars
                slice_gen = SliceGenerator(all_vars, bp=expression_bp)

                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, None, None, None))



        # test
        # from networkx.drawing.nx_agraph import write_dot
        # write_dot(self.state_graph, "testbothg.dot")
        # check if any nodes need to be divided
        for state_node in list(self.state_graph):
            predecessors = list(self.state_graph.predecessors(state_node))
            successors = list(self.state_graph.successors(state_node))
            if len(predecessors) > 1:
                nin = len(predecessors)
                nout = len(successors)
                state_edge = list()
                for edge in known_transitions:
                    if state_node[1:] == edge[1]:
                        state_edge.append(edge)
                ntrans = len(state_edge)
                if ntrans == nin * nout:
                    continue
                else:
                    for pre_node in predecessors:
                        new_id = next(abs_state_id_ctr)
                        print(f"new_id:{new_id}")
                        pre_edge_data = self.state_graph.get_edge_data(pre_node, state_node)
                        self.state_graph.add_node((('NODE_CTR', new_id),) + state_node[1:], outvars=dict(state_node[1:]))
                        self.state_graph.add_edge(pre_node,
                                                  (('NODE_CTR', new_id),) + state_node[1:],
                                                  time_delta=pre_edge_data['time_delta'],
                                                  time_delta_constraint=pre_edge_data['time_delta_constraint'],
                                                  time_delta_src=pre_edge_data['time_delta_src'],
                                                  temp_delta=pre_edge_data['temp_delta'],
                                                  temp_delta_constraint=pre_edge_data['temp_delta_constraint'],
                                                  temp_delta_src=pre_edge_data['temp_delta_src'],
                                                  label=f'time_delta_constraint={pre_edge_data["time_delta_constraint"]}'
                                                  )
                        suc_nodes = [edge[2] for edge in state_edge if edge[0] == pre_node[1:] ]
                        for suc_node in suc_nodes:
                            suc_id = known_states[suc_node]
                            suc_edge_data = self.state_graph.get_edge_data(state_node, ((('NODE_CTR',suc_id),) + suc_node))
                            if suc_edge_data is None:
                                raise RuntimeError("missing edge data while splitting state node")
                            self.state_graph.add_edge((('NODE_CTR', new_id),) + state_node[1:],
                                                      (('NODE_CTR', suc_id),) + suc_node,
                                                      time_delta=suc_edge_data['time_delta'],
                                                      time_delta_constraint=suc_edge_data['time_delta_constraint'],
                                                      time_delta_src=suc_edge_data['time_delta_src'],
                                                      temp_delta=suc_edge_data['temp_delta'],
                                                      temp_delta_constraint=suc_edge_data['temp_delta_constraint'],
                                                      temp_delta_src=suc_edge_data['temp_delta_src'],
                                                      label=f'time_delta_constraint={suc_edge_data["time_delta_constraint"]}'
                                                      )
                    self.state_graph.remove_node(state_node)
                    break   # TODO: this could be wrong if there is multiple nodes need to be divided

        """

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
            # print(simgr.active)
            s = simgr.active[0]
            # print(s)
            if not discover:
                if len(simgr.active) > 1:
                    raise RuntimeError(
                        "scan cycle execution forked into multiple active states"
                    )

            # if s.addr == 0x41FFA0:
            #     print("check time")

            simgr.stash(
                lambda x: x.addr == self._ret_trap,
                from_stash="active",
                to_stash="finished",
            )

            simgr.step()

        # import sys
        # sys.stdout.write('\n')
        if discover:
            return simgr.finished
        else:
            assert len(simgr.finished) == 1
            return simgr.finished[0]


AnalysesHub.register_default("StateGraphRecoveryLifter", StateGraphRecoveryAnalysis)
