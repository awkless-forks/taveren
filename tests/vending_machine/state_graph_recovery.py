from itertools import count
from typing import Optional, List, Dict, Tuple, Set, Callable, Any, TYPE_CHECKING

import itertools
import claripy
import pprint
from angr.sim_options import NO_CROSS_INSN_OPT, SYMBOL_FILL_UNCONSTRAINED_MEMORY, SYMBOL_FILL_UNCONSTRAINED_REGISTERS
from angr.state_plugins.inspect import BP_BEFORE, BP
from angr.analyses.analysis import AnalysesHub
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
        # self.state_graph = networkx.DiGraph()

        # make the initial state
        init_state = self._initialize_state(init_state=self.init_state)
        symbolic_abstate_fields = self._symbolize_var_fields(init_state, self.fields)
        # symbolic_input_fields = self._symbolize_var_fields(init_state, self.fields_input)
        symbolic_time_counters = self._symbolize_timecounter(init_state)
        symbolic_dollar = self._symbolize_dollar(init_state)
        symbolic_quarter = self._symbolize_quarter(init_state)

        # setup inspection points to catch where expressions are created
        all_vars = set(symbolic_abstate_fields.values())
        all_vars |= set(symbolic_time_counters.values())
        all_vars | set(symbolic_dollar.values())
        all_vars | set(symbolic_quarter.values())
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
        self.state_graph.add_node((('NODE_CTR', abs_state_id),) + abs_state, outvars = dict(abs_state))
        state_queue = [(init_state, abs_state_id, abs_state, None, None, None, None, 0, None, None, 0, None, None)]

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
            prev_state, prev_abs_state_id, prev_abs_state, prev_prev_abs, time_delta, time_delta_constraint, time_delta_src, dollar_delta, dollar_constraint, dollar_src, quarter_delta, quarter_constraint, quarter_src = state_queue.pop(0)
            print(prev_abs_state, dollar_delta, dollar_constraint, quarter_delta, quarter_constraint)
            # if prev_abs_state[0][1] == 1 and dollar_delta == 0:
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
            # expression_bp.enabled = True
            next_state = self._traverse_one(prev_state)
            # print(next_state.solver.eval(next_state.memory.load(self._time_addr, 8, endness=self.project.arch.memory_endness)))

            # expression_bp.enabled = False

            abs_state = self.fields.generate_abstract_state(next_state)

            # abs_state += (('time_delta', time_delta),
            #               # ('tdc', time_delta_constraint),
            #               # ('td_src', time_delta_src),
            #               #   ('dollar_delta', dollar_delta),
            #               #   ('dollar_constraint', dollar_constraint),
            #               #   ('dollar_src', dollar_src),
            #               #   ('quarter_delta', quarter_delta),
            #               #   ('quarter_constraint', quarter_constraint),
            #               #   ('quarter_src', quarter_src),
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

            transition = (prev_prev_abs, prev_abs_state, abs_state, dollar_delta, quarter_delta)
            # print(transition)
            if switched_on and transition in known_transitions:
                continue

            known_transitions.append(transition)
            self.state_graph.add_node((('NODE_CTR', abs_state_id),) + abs_state, outvars=dict(abs_state))
            self.state_graph.add_edge((('NODE_CTR', prev_abs_state_id),) + prev_abs_state,
                                      (('NODE_CTR', abs_state_id),) + abs_state,
                                      time_delta=time_delta,
                                      time_delta_constraint=time_delta_constraint,
                                      time_delta_src=time_delta_src,
                                      dollar_delta=dollar_delta,
                                      dollar_constraint=dollar_constraint,
                                      dollar_src=dollar_src,
                                      quarter_delta=quarter_delta,
                                      quarter_constraint=quarter_constraint,
                                      quarter_src=quarter_src,

                                      # label = f'time_delta_constraint={time_delta_constraint},\ndollar_constraint={dollar_constraint}, \nquarter_constraint={quarter_constraint}'
                                      label = f"dollar={dollar_delta}, quarter={quarter_delta}"
                                      )

            # discover time deltas
            # also discover what other input fields are used in the constraints
            # time_delta_and_sources = self._discover_time_deltas(next_state)
            #
            # for delta, constraint, source in time_delta_and_sources:
            #     if source is None:
            #         block_addr, stmt_idx = -1, -1
            #     else:
            #         block_addr, stmt_idx = source
            #     print(f"[.] Discovered a new time interval {delta} defined at {block_addr:#x}:{stmt_idx}")




            dollar_delta_and_sources = self._discover_dollar_deltas(next_state)
            if dollar_delta_and_sources:
                for delta, constraint, source in dollar_delta_and_sources:
                    if source is None:
                        block_addr, stmt_idx = -1, -1
                    else:
                        block_addr, stmt_idx = source
                    print(f"[.] Discovered a new dollar {delta} defined at {block_addr:#x}:{stmt_idx}")
            else:
                dollar_delta_and_sources = [(None, None, None)]

            quarter_delta_and_sources = self._discover_quarter_deltas(next_state)
            if quarter_delta_and_sources:
                for delta, constraint, source in quarter_delta_and_sources:
                    if source is None:
                        block_addr, stmt_idx = -1, -1
                    else:
                        block_addr, stmt_idx = source
                    print(f"[.] Discovered a new quarter {delta} defined at {block_addr:#x}:{stmt_idx}")
            else:
                quarter_delta_and_sources = [(None, None, None)]

            # FIXME: This is a hack. We should fix it later.
            # dollar_delta_and_sources = [(0, None, None), (1, None, None)]
            # quarter_delta_and_sources = [(0, None, None), (1, None, None)]


            # add new work states with deltas to queue
            for (dollar_delta, dollar_constraint, dollar_src), (quarter_delta, quarter_constraint, quarter_src) in itertools.product(*[dollar_delta_and_sources, quarter_delta_and_sources]):

                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                symbolic_time_counters = self._symbolize_timecounter(new_state)
                symbolic_dollar = self._symbolize_dollar(new_state)
                symbolic_quarter = self._symbolize_quarter(new_state)
                all_vars = set(symbolic_abstate_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                all_vars |= set(symbolic_dollar.values())
                all_vars |= set(symbolic_quarter.values())
                all_vars |= self.config_vars
                # slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, dollar_delta, dollar_constraint, dollar_src, quarter_delta, quarter_constraint, quarter_src))
                # state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, 0, None, None, 0, None, None))
                # state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, 1, None, None, 0, None, None))
                # state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, 0, None, None, 1, None, None))




    def _discover_dollar_deltas(self, state: 'SimState') -> List[Tuple[int,claripy.ast.Base,Tuple[int,int]]]:
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
        constraint_source = { }
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        state.inspect.add_breakpoint('constraints', bp_0)

        next_states = self._traverse_one(state, discover=True)
        # detect required dollar delta
        steps: List[Tuple[int,claripy.ast.Base,Tuple[int,int]]] = [ ]
        for next_state in next_states:
            for delta in dollar_deltas:
                for constraint in next_state.solver.constraints:
                    original_constraint = constraint

                    if delta.args[0] in constraint.variables:
                        step = next_state.solver.eval(delta)

                        steps.append((
                            step,
                            constraint,
                            constraint_source.get(original_constraint, None),
                        ))
                        continue

                    else:
                        continue
        print(steps)
        return steps

    def _discover_quarter_deltas(self, state: 'SimState') -> List[Tuple[int,claripy.ast.Base,Tuple[int,int]]]:
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
        constraint_source = { }
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        state.inspect.add_breakpoint('constraints', bp_0)

        next_states = self._traverse_one(state, discover=True)
        # detect required high delta
        steps: List[Tuple[int,claripy.ast.Base,Tuple[int,int]]] = [ ]
        for next_state in next_states:
            for delta in quarter_deltas:
                for constraint in next_state.solver.constraints:
                    original_constraint = constraint

                    if delta.args[0] in constraint.variables:

                        step = next_state.solver.eval(delta)

                        steps.append((
                            step,
                            constraint,
                            constraint_source.get(original_constraint, None),
                        ))
                        continue

                    else:
                        continue
        print(steps)
        return steps

    def _discover_dollar_and_quarter_deltas(self, state: 'SimState'):
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
        bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        state.inspect.add_breakpoint('constraints', bp_0)

        next_states = self._traverse_one(state, discover=True)

        steps = []
        for next_state in next_states:
            dollar_steps = []
            quarter_steps = []
            for constraint in next_state.solver.constraints:
                if dollar_delta.args[0] in constraint.variables:
                    dollar_step = next_state.solver.eval(dollar_delta)
                    if dollar_step is not None:
                        dollar_steps.append((
                            dollar_step,
                            constraint,
                            constraint_source.get(constraint, None),
                        ))
                if quarter_delta.args[0] in constraint.variables:
                    quarter_step = next_state.solver.eval(quarter_delta)
                    if quarter_step is not None:
                        quarter_steps.append((
                            quarter_step,
                            constraint,
                            constraint_source.get(constraint, None),
                        ))
            if len(dollar_steps) > 1 or len(quarter_steps) > 1:
                # find multiple deltas in one state
                # TODO: if there are multiple deltas, we need to AND them as the final constraint
                raise NotImplementedError("multiple deltas in one state are not supported")
            elif len(dollar_steps) == 0:
                dollar_steps.append((None, None, None))
            elif len(quarter_steps) == 0:
                quarter_steps.append((None, None, None))

            steps.append((dollar_steps[0], quarter_steps[0]))

        # print(steps)
        return steps

    def _symbolize_dollar(self, state: 'SimState') -> Dict[str, claripy.ast.Base]:
        (dollar_addr, dollar_sort, dollar_size) = self.dollar_info
        prev = state.globals[dollar_addr]
        prev_dollar = state.solver.eval(prev)
        self.dollar = claripy.BVS('dollar', dollar_size * self.project.arch.byte_width)
        state.globals[dollar_addr] = self.dollar
        state.preconstrainer.preconstrain(claripy.BVV(prev_dollar, dollar_size * self.project.arch.byte_width), self.dollar)
        return {'dollar': self.dollar}

    def _symbolically_advance_dollar(self, state: 'SimState') -> List[claripy.ast.Bits]:
        (dollar_addr, dollar_sort, dollar_size) = self.dollar_info
        # prev = state.globals[dollar_addr]
        # prev_dollar = state.solver.eval(prev)
        dollar_delta = claripy.BVS("dollar_delta", dollar_size * self.project.arch.byte_width)
        state.globals[dollar_addr] = dollar_delta
        # state.preconstrainer.preconstrain(claripy.BVV(prev_dollar, dollar_size * self.project.arch.byte_width),
        #                                   dollar_delta)
        return [dollar_delta]

    def _advance_dollar(self, state: 'SimState', delta) -> None:
        (dollar_addr, dollar_sort, dollar_size) = self.dollar_info
        self.dollar = claripy.BVS('dollar', dollar_size * self.project.arch.byte_width)
        state.globals[dollar_addr] = self.dollar
        state.preconstrainer.preconstrain(claripy.BVV(delta, dollar_size * self.project.arch.byte_width), self.dollar)

    def _symbolize_quarter(self, state: 'SimState') -> Dict[str, claripy.ast.Base]:
        (quarter_addr, quarter_sort, quarter_size) = self.quarter_info
        # prev = state.globals[quarter_addr]
        # prev_quarter = state.solver.eval(prev)
        self.quarter = claripy.BVS('quarter', quarter_size * self.project.arch.byte_width)
        state.globals[quarter_addr] = self.quarter
        # state.preconstrainer.preconstrain(claripy.BVV(prev_quarter, quarter_size * self.project.arch.byte_width), self.quarter)
        return {'quarter': self.quarter}

    def _symbolically_advance_quarter(self, state: 'SimState') -> List[claripy.ast.Bits]:
        (quarter_addr, quarter_sort, quarter_size) = self.quarter_info
        quarter_delta = claripy.BVS("quarter_delta", quarter_size * self.project.arch.byte_width)
        state.globals[quarter_addr] = quarter_delta
        return [quarter_delta]

    def _advance_quarter(self, state: 'SimState', delta) -> None:
        (quarter_addr, quarter_sort, quarter_size) = self.quarter_info
        self.quarter = claripy.BVS('quarter', quarter_size * self.project.arch.byte_width)
        state.globals[quarter_addr] = self.quarter
        state.preconstrainer.preconstrain(claripy.BVV(delta, quarter_size * self.project.arch.byte_width), self.quarter)

    def _initialize_state(self, init_state=None) -> 'SimState':
        if init_state is not None:
            s = init_state.copy()
            s.ip = self.func.addr
            s.globals[10] = 0
            s.globals[11] = 0
        else:
            s = self.project.factory.blank_state(addr=self.func.addr)
            s.regs.rdi = 0xc0000000
            s.memory.store(0xc0000000, b"\x00" * 0x1000)

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

AnalysesHub.register_default('StateGraphRecoveryVendingMachine', StateGraphRecoveryAnalysis)
