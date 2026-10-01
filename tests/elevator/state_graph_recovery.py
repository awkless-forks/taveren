from itertools import count
from typing import Optional, Dict, Set, Callable, Any, TYPE_CHECKING

import claripy
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
        # self.state_graph = networkx.DiGraph()

        # make the initial state
        init_state = self._initialize_state(init_state=self.init_state)
        symbolic_abstate_fields = self._symbolize_var_fields(init_state, self.fields)
        # symbolic_input_fields = self._symbolize_var_fields(init_state, self.fields_input)
        symbolic_time_counters = self._symbolize_timecounter(init_state)
        # symbolic_btn1 = self._symbolize_btn1(init_state)
        # symbolic_btn2 = self._symbolize_btn2(init_state)
        # symbolic_btn3 = self._symbolize_btn3(init_state)
        # symbolic_btn4 = self._symbolize_btn4(init_state)

        # setup inspection points to catch where expressions are created
        all_vars = set(symbolic_abstate_fields.values())
        all_vars |= set(symbolic_time_counters.values())
        # all_vars | set(symbolic_btn1.values())
        # all_vars | set(symbolic_btn2.values())
        # all_vars | set(symbolic_btn3.values())
        # all_vars | set(symbolic_btn4.values())
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
            # if prev_abs_state[0][1] == 1 and low_delta == 0:
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
            # expression_bp.enabled = True
            next_state = self._traverse_one(prev_state)
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
                btn1_delta,
                btn2_delta,
                btn3_delta,
                btn4_delta,
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
                # label = f'time_delta_constraint={time_delta_constraint},\nlow_constraint={low_constraint}, \nhigh_constraint={high_constraint}'
                label=f"btn1={btn1_delta}\nbtn2={btn2_delta}\nbtn3={btn3_delta}\nbtn4={btn4_delta}",
            )

            # # discover time deltas
            # # also discover what other input fields are used in the constraints
            # time_delta_and_sources = self._discover_time_deltas(next_state)
            #
            # for delta, constraint, source in time_delta_and_sources:
            #     if source is None:
            #         block_addr, stmt_idx = -1, -1
            #     else:
            #         block_addr, stmt_idx = source
            #     print(f"[.] Discovered a new time interval {delta} defined at {block_addr:#x}:{stmt_idx}")

            # FIXME: This is a hack. We should fix it later.

            # add new work states with deltas to queue

            new_state = self._initialize_state(init_state=next_state)

            # re-symbolize input fields, time counters, and update slice generator
            symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
            symbolic_time_counters = self._symbolize_timecounter(new_state)
            # symbolic_btn1 = self._symbolize_btn1(new_state)
            # symbolic_btn2 = self._symbolize_btn2(new_state)
            # symbolic_btn3 = self._symbolize_btn3(new_state)
            # symbolic_btn4 = self._symbolize_btn4(new_state)
            all_vars = set(symbolic_abstate_fields.values())
            all_vars |= set(symbolic_time_counters.values())
            # all_vars |= set(symbolic_btn1.values())
            # all_vars |= set(symbolic_btn2.values())
            # all_vars |= set(symbolic_btn3.values())
            # all_vars |= set(symbolic_btn4.values())
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

    # def _discover_low_deltas(self, state: 'SimState') -> List[Tuple[int,claripy.ast.Base,Tuple[int,int]]]:
    #     """
    #     Discover all possible low sensor that may be required to transition the current state to successor states.
    #
    #     :param state:   The current initial state.
    #     :return:        A list of ints where each int represents the required interval in number of seconds.
    #     """
    #     if self.low_sensor is None:
    #         return []
    #     state = self._initialize_state(state)
    #     low_deltas = self._symbolically_advance_low_sensor(state)
    #     # setup inspection points to catch where comparison happens
    #     constraint_source = { }
    #     constraint_logger = ConstraintLogger(constraint_source)
    #     bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
    #     state.inspect.add_breakpoint('constraints', bp_0)
    #
    #     next_states = self._traverse_one(state, discover=True)
    #     # detect required low delta
    #     steps: List[Tuple[int,claripy.ast.Base,Tuple[int,int]]] = [ ]
    #     for next_state in next_states:
    #         for delta in low_deltas:
    #             for constraint in next_state.solver.constraints:
    #                 original_constraint = constraint
    #
    #                 if delta.args[0] in constraint.variables:
    #
    #                     step = next_state.solver.eval(delta)
    #
    #                     steps.append((
    #                         step,
    #                         constraint,
    #                         constraint_source.get(original_constraint, None),
    #                     ))
    #                     continue
    #
    #                 else:
    #                     continue
    #
    #     return steps
    #
    # def _discover_high_deltas(self, state: 'SimState') -> List[Tuple[int,claripy.ast.Base,Tuple[int,int]]]:
    #     """
    #     Discover all possible high sensor that may be required to transition the current state to successor states.
    #
    #     :param state:   The current initial state.
    #     :return:        A list of ints where each int represents the required interval in number of seconds.
    #     """
    #     if self.high_sensor is None:
    #         return []
    #     state = self._initialize_state(state)
    #     high_deltas = self._symbolically_advance_high_sensor(state)
    #     # setup inspection points to catch where comparison happens
    #     constraint_source = { }
    #     constraint_logger = ConstraintLogger(constraint_source)
    #     bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
    #     state.inspect.add_breakpoint('constraints', bp_0)
    #
    #     next_states = self._traverse_one(state, discover=True)
    #     # detect required high delta
    #     steps: List[Tuple[int,claripy.ast.Base,Tuple[int,int]]] = [ ]
    #     for next_state in next_states:
    #         for delta in high_deltas:
    #             for constraint in next_state.solver.constraints:
    #                 original_constraint = constraint
    #
    #                 if delta.args[0] in constraint.variables:
    #
    #                     step = next_state.solver.eval(delta)
    #
    #                     steps.append((
    #                         step,
    #                         constraint,
    #                         constraint_source.get(original_constraint, None),
    #                     ))
    #                     continue
    #
    #                 else:
    #                     continue
    #
    #     return steps
    #
    # def _discover_low_and_high_deltas(self, state: 'SimState'):
    #     """
    #     Discover all possible low and high sensor that may be required to transition the current state to successor states.
    #
    #     :param state:   The current initial state.
    #     :return:        A list of ints where each int represents the required interval in number of seconds.
    #     """
    #     state = self._initialize_state(state)
    #     low_delta = self._symbolically_advance_low_sensor(state)[0]
    #     high_delta = self._symbolically_advance_high_sensor(state)[0]
    #     # setup inspection points to catch where comparison happens
    #     constraint_source = {}
    #     constraint_logger = ConstraintLogger(constraint_source)
    #     bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
    #     state.inspect.add_breakpoint('constraints', bp_0)
    #
    #     next_states = self._traverse_one(state, discover=True)
    #
    #     steps = []
    #     for next_state in next_states:
    #         low_steps = []
    #         high_steps = []
    #         for constraint in next_state.solver.constraints:
    #             if low_delta.args[0] in constraint.variables:
    #                 low_step = next_state.solver.eval(low_delta)
    #                 if low_step is not None:
    #                     low_steps.append((
    #                         low_step,
    #                         constraint,
    #                         constraint_source.get(constraint, None),
    #                     ))
    #             if high_delta.args[0] in constraint.variables:
    #                 high_step = next_state.solver.eval(high_delta)
    #                 if high_step is not None:
    #                     high_steps.append((
    #                         high_step,
    #                         constraint,
    #                         constraint_source.get(constraint, None),
    #                     ))
    #         if len(low_steps) > 1 or len(high_steps) > 1:
    #             # find multiple deltas in one state
    #             # TODO: if there are multiple deltas, we need to AND them as the final constraint
    #         elif len(low_steps) == 0:
    #             low_steps.append((None, None, None))
    #         elif len(high_steps) == 0:
    #             high_steps.append((None, None, None))
    #
    #         steps.append((low_steps[0], high_steps[0]))
    #
    #     # print(steps)
    #     return steps
    #
    # def _discover_btn1_deltas(self, state: 'SimState') -> List[Tuple[int,claripy.ast.Base,Tuple[int,int]]]:
    #     """
    #     Discover all possible water level that may be required to transition the current state to successor states.
    #
    #     :param state:   The current initial state.
    #     :return:        A list of ints where each int represents the required interval in number of seconds.
    #     """
    #     if self.btn1 is None:
    #         return []
    #     state = self._initialize_state(state)
    #     water_deltas = self._symbolically_set_btn1(state)
    #     # setup inspection points to catch where comparison happens
    #     constraint_source = { }
    #     constraint_logger = ConstraintLogger(constraint_source)
    #     bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
    #     state.inspect.add_breakpoint('constraints', bp_0)
    #
    #     next_states = self._traverse_one(state, discover=True)
    #
    #     # detect required water delta
    #     steps: List[Tuple[int,claripy.ast.Base,Tuple[int,int]]] = [ ]
    #     for next_state in next_states:
    #         for delta in water_deltas:
    #             for constraint in next_state.solver.constraints:
    #                 original_constraint = constraint
    #
    #                 if delta.args[0] in constraint.variables:
    #                     step = next_state.solver.min(delta)
    #
    #                     steps.append((
    #                         step,
    #                         constraint,
    #                         constraint_source.get(original_constraint, None),
    #                     ))
    #                     continue
    #
    #                 else:
    #                     continue
    #
    #     return steps

    # def _symbolize_btn1(self, state: 'SimState') -> Dict[str, claripy.ast.Base]:
    #     (btn1_addr, btn1_sort, btn1_size) = self.btn1_info
    #     if btn1_sort == "pin":
    #         prev = state.globals[btn1_addr]
    #         prev_btn1 = state.solver.eval(prev)
    #         self.btn1 = claripy.BVS('btn1', btn1_size * self.project.arch.byte_width)
    #         state.memory.store(btn1_addr, self.btn1, endness=self.project.arch.memory_endness)
    #         state.preconstrainer.preconstrain(claripy.BVV(prev_btn1, btn1_size * self.project.arch.byte_width), self.btn1)
    #         return {'btn1': self.btn1}
    #     else:
    #         print("wrong type")
    #         return {}

    # def _symbolically_set_btn1(self, state: 'SimState') -> List[claripy.ast.Bits]:
    #     (btn1_addr, btn1_sort, btn1_size) = self.btn1_info
    #     btn1_delta = claripy.BVS("btn1_delta", btn1_size * self.project.arch.byte_width)
    #     state.memory.store(btn1_addr, btn1_delta, endness=self.project.arch.memory_endness)
    #     return [btn1_delta]

    def _set_btn1(self, state: "SimState", delta) -> None:
        btn1_addr, btn1_sort, btn1_size = self.btn1_info
        if btn1_sort == "pin":
            state.globals[btn1_addr] = delta

    # def _symbolize_btn2(self, state: 'SimState') -> Dict[str, claripy.ast.Base]:
    #     (btn2_addr, btn2_sort, btn2_size) = self.btn2_info
    #     prev = state.memory.load(btn2_addr, size=btn2_size, endness=self.project.arch.memory_endness)
    #     prev_btn2 = state.solver.eval(prev)
    #     self.btn2 = claripy.BVS('btn2', btn2_size * self.project.arch.byte_width)
    #     state.memory.store(btn2_addr, self.btn1, endness=self.project.arch.memory_endness)
    #     state.preconstrainer.preconstrain(claripy.BVV(prev_btn2, btn2_size * self.project.arch.byte_width), self.btn2)
    #     return {'btn2': self.btn2}

    # def _symbolically_set_btn2(self, state: 'SimState') -> List[claripy.ast.Bits]:
    #     (btn2_addr, btn2_sort, btn2_size) = self.btn2_info
    #     btn2_delta = claripy.BVS("btn2_delta", btn2_size * self.project.arch.byte_width)
    #     state.memory.store(btn2_addr, btn2_delta, endness=self.project.arch.memory_endness)
    #     return [btn2_delta]

    def _set_btn2(self, state: "SimState", delta) -> None:
        btn2_addr, btn2_sort, btn2_size = self.btn2_info
        if btn2_sort == "pin":
            state.globals[btn2_addr] = delta

    # def _symbolize_btn3(self, state: 'SimState') -> Dict[str, claripy.ast.Base]:
    #     (btn3_addr, btn3_sort, btn3_size) = self.btn3_info
    #     prev = state.memory.load(btn3_addr, size=btn3_size, endness=self.project.arch.memory_endness)
    #     prev_btn3 = state.solver.eval(prev)
    #     self.btn3 = claripy.BVS('btn3', btn3_size * self.project.arch.byte_width)
    #     state.memory.store(btn3_addr, self.btn1, endness=self.project.arch.memory_endness)
    #     state.preconstrainer.preconstrain(claripy.BVV(prev_btn3, btn3_size * self.project.arch.byte_width), self.btn3)
    #     return {'btn3': self.btn3}

    # def _symbolically_set_btn3(self, state: 'SimState') -> List[claripy.ast.Bits]:
    #     (btn3_addr, btn3_sort, btn3_size) = self.btn3_info
    #     btn3_delta = claripy.BVS("btn3_delta", btn3_size * self.project.arch.byte_width)
    #     state.memory.store(btn3_addr, btn3_delta, endness=self.project.arch.memory_endness)
    #     return [btn3_delta]

    def _set_btn3(self, state: "SimState", delta) -> None:
        btn3_addr, btn3_sort, btn3_size = self.btn3_info
        if btn3_sort == "pin":
            state.globals[btn3_addr] = delta

    # def _symbolize_btn4(self, state: 'SimState') -> Dict[str, claripy.ast.Base]:
    #     (btn4_addr, btn4_sort, btn4_size) = self.btn4_info
    #     prev = state.memory.load(btn4_addr, size=btn4_size, endness=self.project.arch.memory_endness)
    #     prev_btn4 = state.solver.eval(prev)
    #     self.btn4 = claripy.BVS('btn4', btn4_size * self.project.arch.byte_width)
    #     state.memory.store(btn4_addr, self.btn1, endness=self.project.arch.memory_endness)
    #     state.preconstrainer.preconstrain(claripy.BVV(prev_btn4, btn4_size * self.project.arch.byte_width), self.btn4)
    #     return {'btn4': self.btn4}

    # def _symbolically_set_btn4(self, state: 'SimState') -> List[claripy.ast.Bits]:
    #     (btn4_addr, btn4_sort, btn4_size) = self.btn4_info
    #     btn4_delta = claripy.BVS("btn4_delta", btn4_size * self.project.arch.byte_width)
    #     state.memory.store(btn4_addr, btn4_delta, endness=self.project.arch.memory_endness)
    #     return [btn4_delta]

    def _set_btn4(self, state: "SimState", delta) -> None:
        btn4_addr, btn4_sort, btn4_size = self.btn4_info
        if btn4_sort == "pin":
            state.globals[btn4_addr] = delta

    def _traverse_one(self, state: "SimState", discover: bool = False):

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

        # import sys
        # sys.stdout.write('\n')
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
