from itertools import count
from typing import Optional, List, Dict, Tuple, Set, Callable, Any, TYPE_CHECKING

import claripy
import pprint
from angr.analyses.analysis import AnalysesHub
from angr.utils.timing import timethis
from taveren.state_graph_recovery import ConstraintLogger, MultiDiGraph_DedupeEdge, StateGraphRecoveryBase

if TYPE_CHECKING:
    from angr import SimState
    from angr.knowledge_plugins.functions import Function
    from .abstract_state import AbstractStateFields


class StateGraphRecoveryAnalysis(StateGraphRecoveryBase):
    """
    Traverses a function and derive a state graph with respect to given variables.
    """
    def __init__(self, func: 'Function', fields: 'AbstractStateFields', software: str,
                 time_addr: int, temp_addr: int = None,
                 init_state: Optional['SimState']=None,
                 inputs:Dict=None,
                 fields_input: Optional[Any]=None,
                 switch_on: Optional[Callable]=None,
                 printstate: Optional[Callable]=None,
                 config_vars: Optional[Set[claripy.ast.Base]]=None,
                 patch_callback: Optional[Callable]=None):
        self.func = func
        self.fields = fields
        self.config_vars = config_vars if config_vars is not None else set()
        self.software = software
        self.init_state = init_state
        self.inputs = inputs
        self.fields_input = fields_input
        self._switch_on = switch_on
        self._ret_trap: int = 0x1f37ff4a
        self.printstate = printstate
        self.patch_callback = patch_callback

        self._time_addr = time_addr
        self.car_on_start_info = inputs["CAR_ON_START_SENSOR"]
        self.service_selection_info = inputs["SERVICE_SELECTION_BUTTON"]
        self.car_on_start = None
        self.service_selection = None
        self._tv_sec_var = None
        self.state_graph = None
        self._expression_source = {}
        self.iter_count = 0
        self.traverse()
        print("iter count: ", self.iter_count)

    def traverse(self):

        # create an empty state graph
        self.state_graph = MultiDiGraph_DedupeEdge()
        # self.state_graph = networkx.DiGraph()

        # make the initial state
        init_state = self._initialize_state(init_state=self.init_state)
        symbolic_abstate_fields = self._symbolize_var_fields(init_state, self.fields)
        # symbolic_input_fields = self._symbolize_var_fields(init_state, self.fields_input)
        symbolic_time_counters = self._symbolize_timecounter(init_state)
        symbolic_car_on_start = self._symbolize_car_on_start(init_state)
        symbolic_service_selection = self._symbolize_service_selection(init_state)

        # setup inspection points to catch where expressions are created
        all_vars = set(symbolic_abstate_fields.values())
        all_vars |= set(symbolic_time_counters.values())
        all_vars | set(symbolic_car_on_start.values())
        all_vars | set(symbolic_service_selection.values())
        # slice_gen = SliceGenerator(all_vars, bp=None)
        # expression_bp = slice_gen.install_expr_hook(init_state)

        # setup inspection points to catch where expressions are written to registers
        #expression_logger = ExpressionLogger(self._expression_source, { v.args[0] for v in all_vars })
        #regwrite_bp = BP(when=BP_BEFORE, enabled=True, action=expression_logger.on_register_write)
        #init_state.inspect.add_breakpoint('reg_write', regwrite_bp)
        #memread_bp = BP(when=BP_AFTER, enabled=True, action=expression_logger.on_memory_read)
        #init_state.inspect.add_breakpoint('mem_read', memread_bp)

        # Abstract state ID counter
        abs_state_id_ctr = count(0)

        abs_state = self.fields.generate_abstract_state(init_state)
        abs_state_id = next(abs_state_id_ctr)
        self.state_graph.add_node((('NODE_CTR', abs_state_id),) + abs_state, outvars = dict(abs_state))
        state_queue = [(init_state, abs_state_id, abs_state, None, None, None, None, None, None, None, None, None, None)]

        switched_on = False if self._switch_on else True
        '''
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
        '''
        known_transitions = list()
        known_states = dict()
        absstate_to_slice = { }
        while state_queue:
            (prev_state, prev_abs_state_id, prev_abs_state, prev_prev_abs, time_delta, time_delta_constraint, time_delta_src,
             car_on_start_delta, car_on_start_constraint, car_on_start_src,
             service_selection_delta, service_selection_constraint, service_selection_src) = state_queue.pop(0)
            print(f"State queue length: {len(state_queue)}")
            print(prev_abs_state, car_on_start_delta, car_on_start_constraint, car_on_start_src, service_selection_delta, service_selection_constraint, service_selection_src)

            # if len(known_transitions) > 3:
            #     known_delta_transitions = [(t[0], t[1], t[3], t[4], t[5]) for t in known_transitions if
            #                                t[0] == prev_prev_abs and t[1] == prev_abs_state and t[3] == time_delta and
            #                                t[4] == car_on_start_delta and t[5] == service_selection_delta]
            #     if known_delta_transitions:
            #         print("!!! aggressive deduplication")
            #         # fixme: aggressive deduplication
            #         continue
            if time_delta is None:
                pass
            else:
                # advance the time stamp as required
                self._advance_timecounter(prev_state, time_delta)
            if car_on_start_delta is not None:
                self._advance_car_on_start(prev_state, car_on_start_delta)
            if service_selection_delta is not None:
                self._advance_service_selection(prev_state, service_selection_delta)

            # symbolically trace the state
            # expression_bp.enabled = True
            next_state = self._traverse_one(prev_state)
            # print(next_state.solver.eval(next_state.memory.load(self._time_addr, 8, endness=self.project.arch.memory_endness)))

            # expression_bp.enabled = False

            abs_state = self.fields.generate_abstract_state(next_state)

            abs_state += (('time_delta', time_delta),
                          )
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

            transition = (prev_prev_abs, prev_abs_state, abs_state, time_delta, car_on_start_delta, service_selection_delta)
            # print(transition)
            if switched_on and transition in known_transitions:
                print(f"[+] Skip a known transition {transition} among {len(known_transitions)} known transitions.")
                continue

            known_transitions.append(transition)
            self.state_graph.add_node((('NODE_CTR', abs_state_id),) + abs_state, outvars=dict(abs_state))
            self.state_graph.add_edge((('NODE_CTR', prev_abs_state_id),) + prev_abs_state,
                                      (('NODE_CTR', abs_state_id),) + abs_state,
                                      time_delta=time_delta,
                                      time_delta_constraint=time_delta_constraint,
                                      time_delta_src=time_delta_src,
                                      car_on_start_delta=car_on_start_delta,
                                      car_on_start_constraint=car_on_start_constraint,
                                      car_on_start_src=car_on_start_src,
                                      service_selection_delta=service_selection_delta,
                                      service_selection_constraint=service_selection_constraint,
                                      service_selection_src=service_selection_src,

                                      # label = f'time_delta_constraint={time_delta_constraint},\nlow_constraint={low_constraint}, \nhigh_constraint={high_constraint}'
                                      # label = f"water_level_delta={water_level_delta}"
                                      label = f"time_delta={time_delta},\ncar_on_start_delta={car_on_start_delta},\nservice_selection_delta={service_selection_delta}"
                                      )

            # discover time deltas
            # also discover what other input fields are used in the constraints
            time_delta_and_sources = self._discover_time_deltas(next_state)

            for time_delta, time_constraint, time_source in time_delta_and_sources:
                if time_source is None:
                    block_addr, stmt_idx = -1, -1
                else:
                    block_addr, stmt_idx = time_source
                print(f"[.] Discovered a new time interval {time_delta} defined at {block_addr:#x}:{stmt_idx}")


                # append state satisfy constraint
                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                symbolic_time_counters = self._symbolize_timecounter(new_state)
                symbolic_car_on_start = self._symbolize_car_on_start(new_state)
                symbolic_service_selection = self._symbolize_service_selection(new_state)
                all_vars = set(symbolic_abstate_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                all_vars |= set(symbolic_car_on_start.values())
                all_vars |= set(symbolic_service_selection.values())
                all_vars |= self.config_vars
                # slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                # FIXME: this is a hack, product time with other deltas
                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, time_delta, time_constraint,
                                    time_source, None, None, None, None, None, None))


            car_on_start_delta_and_sources = self._discover_car_on_start_deltas(next_state)
            for car_on_start_delta, car_on_start_constraint, car_on_start_src in car_on_start_delta_and_sources:
                if car_on_start_src is None:
                    block_addr, stmt_idx = -1, -1
                else:
                    block_addr, stmt_idx = car_on_start_src
                print(f"[.] Discovered a new car_on_start {car_on_start_delta} defined at {block_addr:#x}:{stmt_idx}")

                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                symbolic_time_counters = self._symbolize_timecounter(new_state)
                symbolic_car_on_start = self._symbolize_car_on_start(new_state)
                symbolic_service_selection = self._symbolize_service_selection(new_state)
                all_vars = set(symbolic_abstate_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                all_vars |= set(symbolic_car_on_start.values())
                all_vars |= set(symbolic_service_selection.values())
                all_vars |= self.config_vars
                # slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None,
                                    car_on_start_delta, car_on_start_constraint, car_on_start_src,
                                    None, None, None))

            # if self.iter_count < 5:
            service_selection_delta_and_sources = self._discover_service_selection_deltas(next_state)

            for service_selection_delta, service_selection_constraint, service_selection_src in service_selection_delta_and_sources:
                if service_selection_src is None:
                    block_addr, stmt_idx = -1, -1
                else:
                    block_addr, stmt_idx = service_selection_src
                print(f"[.] Discovered a new service_selection {service_selection_delta} defined at {block_addr:#x}:{stmt_idx}")

                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                symbolic_time_counters = self._symbolize_timecounter(new_state)
                symbolic_car_on_start = self._symbolize_car_on_start(new_state)
                symbolic_service_selection = self._symbolize_service_selection(new_state)
                all_vars = set(symbolic_abstate_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                all_vars |= set(symbolic_car_on_start.values())
                all_vars |= set(symbolic_service_selection.values())
                all_vars |= self.config_vars
                # slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None,
                                    None, None, None,
                                    service_selection_delta, service_selection_constraint, service_selection_src))
            self.iter_count += 1
            # FIXME: This is a hack. We should fix it later.
            # low_delta_and_sources = [(0, None, None), (1, None, None)]
            # high_delta_and_sources = [(0, None, None), (1, None, None)]


            # add new work states with deltas to queue
            # for (car_on_start_delta, car_on_start_constraint, car_on_start_src), (service_selection_delta, service_selection_constraint, service_selection_src) in self._discover_two_deltas(next_state):
            #     new_state = self._initialize_state(init_state=next_state)
            #
            #     # re-symbolize input fields, time counters, and update slice generator
            #     symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
            #     symbolic_time_counters = self._symbolize_timecounter(new_state)
            #     symbolic_car_on_start = self._symbolize_car_on_start(new_state)
            #     symbolic_service_selection = self._symbolize_service_selection(new_state)
            #     all_vars = set(symbolic_abstate_fields.values())
            #     all_vars |= set(symbolic_time_counters.values())
            #     all_vars |= set(symbolic_car_on_start.values())
            #     all_vars |= set(symbolic_service_selection.values())
            #     all_vars |= self.config_vars
            #     slice_gen = SliceGenerator(all_vars, bp=expression_bp)
            #     state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None,
            #                         car_on_start_delta, car_on_start_constraint, car_on_start_src,
            #                         service_selection_delta, service_selection_constraint, service_selection_src))

        '''

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

        '''

        # print("!!!! analysis ended, check transitions")

    @timethis
    def _discover_time_deltas(self, state: 'SimState') -> List[Tuple[int,claripy.ast.Base,Tuple[int,int]]]:
        """
        Discover all possible time intervals that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """

        state = self._initialize_state(state)
        time_deltas = self._symbolically_advance_timecounter(state)
        # setup inspection points to catch where comparison happens
        constraint_source = { }
        constraint_logger = ConstraintLogger(constraint_source)
        #bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        #state.inspect.add_breakpoint('constraints', bp_0)

        next_state = self._traverse_one(state)
        # detect required time delta
        # TODO: Extend it to more than just seconds
        steps: List[Tuple[int,claripy.ast.Base,Tuple[int,int]]] = [ ]
        if time_deltas:
            for delta in time_deltas:
                for constraint in next_state.solver.constraints:

                    original_constraint = constraint
                    # attempt simplification if this constraint has both config variables and time delta variables
                    if any(x.args[0] in constraint.variables for x in self.config_vars) and delta.args[0] in constraint.variables:
                        simplified_constraint, self._expression_source = self._simplify_constraint(constraint,
                                                                                                   self._expression_source)
                        if simplified_constraint is not None:
                            constraint = simplified_constraint

                    if constraint.op == "__eq__" and constraint.args[0] is delta:
                        continue
                    # if delta.args[0] in constraint.variables:
                    #     print("!!!! check time delta !!!!!!!")
                    elif constraint.op in ('ULE'):  # arduino arm32
                        if constraint.args[0].args[1] is delta:
                            if constraint.args[1].args[0].op == 'BVV':
                                step = constraint.args[1].args[0].args[0]
                                if step != 0:
                                    steps.append((
                                        step,
                                        constraint,
                                        constraint_source.get(original_constraint, None),
                                    ))
                                    continue
                    elif constraint.op in ("__le__",):  # simulink arm32
                        if constraint.args[0].args[1] is delta:
                            if constraint.args[1].op == 'BVV':
                                step = constraint.args[1].args[0]
                                if step != 0 and step < 255:
                                    steps.append((
                                        step,
                                        constraint,
                                        constraint_source.get(original_constraint, None),
                                    ))
                                    continue
                            elif constraint.args[1].args[0].op == 'BVV':    # arduino arm32 oven
                                step = constraint.args[1].args[0].args[0]
                                if step != 0:
                                    steps.append((
                                        step,
                                        constraint,
                                        constraint_source.get(original_constraint, None),
                                    ))
                                    continue
                    elif constraint.op == "__ne__":
                        if constraint.args[0] is delta:     # amd64
                            # found a potential step
                            if constraint.args[1].op == 'BVV':
                                step = constraint.args[1].concrete_value
                                if step != 0 and step < 255:
                                    steps.append((
                                        step,
                                        constraint,
                                        constraint_source.get(original_constraint, None),
                                    ))
                                    continue
                            else:
                                # attempt to evaluate the right-hand side
                                values = state.solver.eval_upto(constraint.args[1], 2)
                                if len(values) == 1:
                                    # it has a single value!
                                    step = values[0]
                                    if step != 0:
                                        steps.append((
                                            step,
                                            constraint,
                                            constraint_source.get(original_constraint, None),
                                        ))
                                        continue

                        if constraint.args[1].op == "BVS":      # arm32
                            # access constraint.args[1].args[2]
                            if constraint.args[1].args[2] is delta or constraint.args[1] is delta:
                                if constraint.args[0].op == 'BVV':
                                    step = constraint.args[0].args[0]
                                    if step != 0:
                                        steps.append((
                                            step,
                                            constraint,
                                            constraint_source.get(original_constraint, None),
                                        ))
                                        continue
        return steps



    @timethis
    def _discover_car_on_start_deltas(self, state: 'SimState') -> List[Tuple[int,claripy.ast.Base,Tuple[int,int]]]:
        """
        Discover all possible car_on_start sensor that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """
        if self.car_on_start is None:
            return []
        state = self._initialize_state(state)
        car_on_start_deltas = self._symbolically_advance_car_on_start(state)
        # setup inspection points to catch where comparison happens
        constraint_source = { }
        constraint_logger = ConstraintLogger(constraint_source)
        #bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        #state.inspect.add_breakpoint('constraints', bp_0)

        next_state = self._traverse_one(state)
        # detect required car_on_start delta
        steps: List[Tuple[int,claripy.ast.Base,Tuple[int,int]]] = [ ]
        for delta in car_on_start_deltas:
            constraints_with_delta = [constraint for constraint in next_state.solver.constraints if delta.args[0] in constraint.variables]
            if len(constraints_with_delta) > 0:
                    # TODO: AND all the constraints with delta, and negate it to get the new constraint
                    # print("!!!! check car_on_start delta !!!!!!!")

                    new_constraint = claripy.Not(claripy.And(*constraints_with_delta))
                    blank = self.project.factory.blank_state()
                    blank.solver.add(new_constraint)
                    step = blank.solver.eval(delta)

                    steps.append((
                        step,
                        new_constraint,
                        constraint_source.get(constraints_with_delta[-1], None),
                    ))
                    continue

            else:
                continue

        return steps

    def _discover_two_deltas(self, state: 'SimState'):
        """
        Discover all possible car_om_start and selection_button that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """
        state = self._initialize_state(state)
        car_on_start_delta = self._symbolically_advance_car_on_start(state)[0]
        service_selection_delta = self._symbolically_advance_service_selection(state)[0]
        # setup inspection points to catch where comparison happens
        constraint_source = {}
        constraint_logger = ConstraintLogger(constraint_source)
        #bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        #state.inspect.add_breakpoint('constraints', bp_0)

        next_states = self._traverse_one(state, discover=True)

        steps = []
        for next_state in next_states:
            car_on_start_steps = []
            service_selsction_steps = []
            for constraint in next_state.solver.constraints:
                if car_on_start_delta.args[0] in constraint.variables:
                    car_on_start_step = next_state.solver.eval(car_on_start_delta)
                    if car_on_start_step is not None:
                        car_on_start_steps.append((
                            car_on_start_step,
                            constraint,
                            constraint_source.get(constraint, None),
                        ))
                if service_selection_delta.args[0] in constraint.variables:
                    service_selection_step = next_state.solver.min(service_selection_delta)
                    if service_selection_step is not None:
                        service_selsction_steps.append((
                            service_selection_step,
                            constraint,
                            constraint_source.get(constraint, None),
                        ))
            if len(car_on_start_steps) > 1 or len(service_selsction_steps) > 1:
                # find multiple deltas in one state
                # TODO: if there are multiple deltas, we need to AND them as the final constraint
                raise NotImplementedError("multiple deltas in one state are not supported")
            elif len(car_on_start_steps) == 0:
                car_on_start_steps.append((None, None, None))
            elif len(service_selsction_steps) == 0:
                service_selsction_steps.append((None, None, None))

            steps.append((car_on_start_steps[0], service_selsction_steps[0]))

        print(steps)
        return steps

    @timethis
    def _discover_service_selection_deltas(self, state: 'SimState') -> List[Tuple[int,claripy.ast.Base,Tuple[int,int]]]:
        """
        Discover all possible service_selsction that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """
        if self.service_selection is None:
            return []
        state = self._initialize_state(state)
        service_selection_deltas = self._symbolically_advance_service_selection(state)
        # setup inspection points to catch where comparison happens
        constraint_source = { }
        constraint_logger = ConstraintLogger(constraint_source)
        #bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        #state.inspect.add_breakpoint('constraints', bp_0)

        next_states = self._traverse_one(state, discover=True)

        # detect required water delta
        steps: List[Tuple[int,claripy.ast.Base,Tuple[int,int]]] = [ ]
        for next_state in next_states:
            for delta in service_selection_deltas:
                for constraint in next_state.solver.constraints:
                    original_constraint = constraint

                    if delta.args[0] in constraint.variables:
                        # print("!!!! check service_selection delta !!!!!!!")
                        step = next_state.solver.min(delta)
                        if step not in [x[0] for x in steps]:
                            steps.append((
                                step,
                                constraint,
                                constraint_source.get(original_constraint, None),
                            ))
                        continue

                    else:
                        continue

        return steps

    # Traffic_Light Beremiz
    def _symbolize_timecounter_beremiz(self, state: 'SimState') -> Dict[str,claripy.ast.Base]:
        tv_sec_addr = self._time_addr
        tv_nsec_addr = tv_sec_addr + 4

        self._tv_sec_var = claripy.BVS('tv_sec', 4 * self.project.arch.byte_width)
        # self._tv_nsec_var = claripy.BVS('tv_nsec', self.project.arch.bytes * self.project.arch.byte_width)
        self._tv_nsec_var = claripy.BVV(1, 4 * self.project.arch.byte_width)

        state.memory.store(tv_sec_addr, self._tv_sec_var, endness=self.project.arch.memory_endness)
        state.memory.store(tv_nsec_addr, self._tv_nsec_var, endness=self.project.arch.memory_endness)

        # the initial timer values are 0
        state.preconstrainer.preconstrain(claripy.BVV(0, 4 * self.project.arch.byte_width), self._tv_sec_var)
        # state.preconstrainer.preconstrain(claripy.BVV(0, self.project.arch.bytes * self.project.arch.byte_width), self._tv_nsec_var)

        return {
            'tv_sec_var': self._tv_sec_var
        }

    def _symbolically_advance_timecounter(self, state: 'SimState') -> List[claripy.ast.Bits]:
        bytesize = 4
        if self.software == 'simulink':
            bytesize = 1
        sec_delta = claripy.BVS("sec_delta", bytesize * self.project.arch.byte_width)
        state.preconstrainer.preconstrain(claripy.BVV(1, bytesize * self.project.arch.byte_width), sec_delta)

        tv_sec = state.memory.load(self._time_addr, size=bytesize, endness=self.project.arch.memory_endness)
        state.memory.store(self._time_addr, tv_sec + sec_delta, endness=self.project.arch.memory_endness)

        return [sec_delta]

    def _advance_timecounter(self, state: 'SimState', delta: int) -> None:
        bytesize = 4
        if self.software == 'simulink':
            bytesize = 1
        prev = state.memory.load(self._time_addr, size=bytesize, endness=self.project.arch.memory_endness)
        state.memory.store(self._time_addr, prev + delta, endness=self.project.arch.memory_endness)

        if self.software == 'beremiz':
            tv_nsec = state.memory.load(self._time_addr + 4, size=self.project.arch.bytes,
                                        endness=self.project.arch.memory_endness)
            state.memory.store(self._time_addr + 4, tv_nsec + 200,
                               endness=self.project.arch.memory_endness)

    def _symbolize_car_on_start(self, state: 'SimState') -> Dict[str, claripy.ast.Base]:
        (car_on_start_addr, car_on_start_sort, car_on_start_size) = self.car_on_start_info
        prev = state.memory.load(car_on_start_addr, size=car_on_start_size, endness=self.project.arch.memory_endness)
        prev_car_on_start = state.solver.eval(prev)
        self.car_on_start = claripy.BVS('car_on_start', car_on_start_size * self.project.arch.byte_width)
        state.memory.store(car_on_start_addr, self.car_on_start, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.BVV(prev_car_on_start, car_on_start_size * self.project.arch.byte_width), self.car_on_start)
        return {'car_on_start': self.car_on_start}

    def _symbolically_advance_car_on_start(self, state: 'SimState') -> List[claripy.ast.Bits]:
        (car_on_start_addr, car_on_start_sort, car_on_start_size) = self.car_on_start_info
        prev = state.memory.load(car_on_start_addr, size=car_on_start_size, endness=self.project.arch.memory_endness)
        prev_car_on_start = state.solver.eval(prev)
        car_on_start_delta = claripy.BVS("car_on_start_delta", car_on_start_size * self.project.arch.byte_width)
        state.memory.store(car_on_start_addr, car_on_start_delta, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(
            claripy.BVV(prev_car_on_start, car_on_start_size * self.project.arch.byte_width), car_on_start_delta)
        return [car_on_start_delta]

    def _advance_car_on_start(self, state: 'SimState', delta) -> None:
        (car_on_start_addr, car_on_start_sort, car_on_start_size) = self.car_on_start_info
        self.car_on_start = claripy.BVS('car_on_start', car_on_start_size * self.project.arch.byte_width)
        state.memory.store(car_on_start_addr, self.car_on_start, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.BVV(delta, car_on_start_size * self.project.arch.byte_width), self.car_on_start)


    def _symbolize_service_selection(self, state: 'SimState') -> Dict[str, claripy.ast.Base]:
        (service_selection_addr, service_selection_sort, service_selection_size) = self.service_selection_info
        prev = state.memory.load(service_selection_addr, size=service_selection_size, endness=self.project.arch.memory_endness)
        prev_service_selection = state.solver.eval(prev)
        self.service_selection = claripy.BVS('service_selection', service_selection_size * self.project.arch.byte_width)
        state.memory.store(service_selection_addr, self.service_selection, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.BVV(prev_service_selection, service_selection_size * self.project.arch.byte_width), self.service_selection)
        return {'service_selection': self.service_selection}

    def _symbolically_advance_service_selection(self, state: 'SimState') -> List[claripy.ast.Bits]:
        (service_selection_addr, service_selection_sort, service_selection_size) = self.service_selection_info
        service_selection_delta = claripy.BVS("service_selection_delta", service_selection_size * self.project.arch.byte_width)
        state.memory.store(service_selection_addr, service_selection_delta, endness=self.project.arch.memory_endness)
        return [service_selection_delta]

    def _advance_service_selection(self, state: 'SimState', delta) -> None:
        (service_selection_addr, service_selection_sort, service_selection_size) = self.service_selection_info
        self.service_selection = claripy.BVS('service_selection', service_selection_size * self.project.arch.byte_width)
        state.memory.store(service_selection_addr, self.service_selection, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.BVV(delta, service_selection_size * self.project.arch.byte_width), self.service_selection)

    @timethis
    def _traverse_one(self, state: 'SimState', discover: bool = False):

        simgr = self.project.factory.simgr(state)

        while simgr.active:
            # print(simgr.active)
            s = simgr.active[0]
            # print(s)
            if not discover:
                if len(simgr.active) > 1:
                    raise RuntimeError("scan cycle execution forked into multiple active states")

            if s.addr == 0x423D67:
                print("CMP LOW !!!!!!!!!!!!!!!!!!!" )
            if s.addr == 0x423E3B:
                print("CMP HIGH !!!!!!!!!!!!!!!!!!!" )

            simgr.stash(lambda x: x.addr == self._ret_trap, from_stash='active', to_stash='finished')

            simgr.step()

        # import sys
        # sys.stdout.write('\n')
        if discover:
            return simgr.finished
        else:
            assert len(simgr.finished) == 1
            return simgr.finished[0]


AnalysesHub.register_default('StateGraphRecoveryCarWash', StateGraphRecoveryAnalysis)
