from itertools import count
from typing import Optional, List, Dict, Tuple, Set, Callable, Any, TYPE_CHECKING

import claripy
import pprint
from angr.sim_options import NO_CROSS_INSN_OPT, SYMBOL_FILL_UNCONSTRAINED_MEMORY, SYMBOL_FILL_UNCONSTRAINED_REGISTERS
from angr.state_plugins.inspect import BP_BEFORE, BP_AFTER, BP
from angr.analyses.analysis import AnalysesHub
from taveren.state_graph_recovery import ConstraintLogger, ExpressionLogger, SliceGenerator, MultiDiGraph_DedupeEdge, StateGraphRecoveryBase

if TYPE_CHECKING:
    from angr import SimState
    from .abstract_state import AbstractStateFields


class StateGraphRecoveryAnalysis(StateGraphRecoveryBase):
    """
    Traverses a function and derive a state graph with respect to given variables.
    """
    def __init__(self, func: int, fields: 'AbstractStateFields', software: str,
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
        self.ichar_info = inputs["c"]
        self.ichar = None
        self._tv_sec_var = None
        # self._temperature = None
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
        # symbolic_time_counters = self._symbolize_timecounter(init_state)
        symbolic_ichar = self._symbolize_ichar(init_state)

        # setup inspection points to catch where expressions are created
        all_vars = set(symbolic_abstate_fields.values())
        # all_vars |= set(symbolic_time_counters.values())
        all_vars | set(symbolic_ichar.values())
        slice_gen = SliceGenerator(all_vars, bp=None)
        expression_bp = slice_gen.install_expr_hook(init_state)

        # setup inspection points to catch where expressions are written to registers
        expression_logger = ExpressionLogger(self._expression_source, { v.args[0] for v in all_vars })
        regwrite_bp = BP(when=BP_BEFORE, enabled=True, action=expression_logger.on_register_write)
        init_state.inspect.add_breakpoint('reg_write', regwrite_bp)
        memread_bp = BP(when=BP_AFTER, enabled=True, action=expression_logger.on_memory_read)
        init_state.inspect.add_breakpoint('mem_read', memread_bp)

        # Abstract state ID counter
        abs_state_id_ctr = count(0)

        abs_state = self.fields.generate_abstract_state(init_state)
        abs_state_id = next(abs_state_id_ctr)
        self.state_graph.add_node((('NODE_CTR', abs_state_id),) + abs_state, outvars = dict(abs_state))
        state_queue = [(init_state, abs_state_id, abs_state, None, None, None, None)]

        switched_on = False if self._switch_on else True


        # add new work states with deltas to queue
        for ichar_delta, ichar_constraint, ichar_src in self._discover_ichar_deltas(init_state):
            if ichar_src is None:
                block_addr, stmt_idx = -1, -1
            else:
                block_addr, stmt_idx = ichar_src
            print(f"[.] Discovered a new input character {chr(ichar_delta)} ({ichar_delta}) defined at {block_addr:#x}:{stmt_idx}")

            new_state = self._initialize_state(init_state=init_state)

            # re-symbolize input fields, time counters, and update slice generator
            symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
            # symbolic_time_counters = self._symbolize_timecounter(new_state)
            symbolic_ichar = self._symbolize_ichar(new_state)
            all_vars = set(symbolic_abstate_fields.values())
            # all_vars |= set(symbolic_time_counters.values())
            all_vars |= set(symbolic_ichar.values())
            # all_vars |= self.config_vars
            slice_gen = SliceGenerator(all_vars, bp=expression_bp)
            state_queue.append((new_state, abs_state_id, abs_state, None, ichar_delta, ichar_constraint, ichar_src))


        known_transitions = list()
        known_states = dict()
        absstate_to_slice = { }
        while state_queue:
            prev_state, prev_abs_state_id, prev_abs_state, prev_prev_abs, ichar_delta, ichar_constraint, ichar_src = state_queue.pop(0)
            print(prev_abs_state, ichar_delta, ichar_constraint, ichar_src)
            # if prev_abs_state[0][1] == 1 and low_delta == 0:
            # if time_delta is None:
            #     pass
            # else:
            #     # advance the time stamp as required
            #     self._advance_timecounter(prev_state, time_delta)
            if ichar_delta is not None:
                self._advance_ichar(prev_state, ichar_delta)

            # symbolically trace the state
            expression_bp.enabled = True
            next_state = self._traverse_one(prev_state)
            # print(next_state.solver.eval(next_state.memory.load(self._time_addr, 8, endness=self.project.arch.memory_endness)))

            expression_bp.enabled = False

            abs_state = self.fields.generate_abstract_state(next_state)

            if next_state.addr == self._ret_trap:
                abs_state += (("returned", 1),)
            elif next_state.addr == 0x4018cb:
                abs_state += (("returned", 0),)

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
            absstate_to_slice[abs_state] = slice_gen.slice
            print("[.] There are %d nodes in the slice." % len(slice_gen.slice))

            transition = (prev_prev_abs, prev_abs_state, abs_state, ichar_delta)
            # print(transition)
            if switched_on and transition in known_transitions:
                continue

            known_transitions.append(transition)
            self.state_graph.add_node((('NODE_CTR', abs_state_id),) + abs_state, outvars=dict(abs_state))
            self.state_graph.add_edge((('NODE_CTR', prev_abs_state_id),) + prev_abs_state,
                                      (('NODE_CTR', abs_state_id),) + abs_state,
                                      # time_delta=time_delta,
                                      # time_delta_constraint=time_delta_constraint,
                                      # time_delta_src=time_delta_src,
                                      ichar_delta=ichar_delta,
                                      ichar_constraint=ichar_constraint,
                                      ichar_src=ichar_src,

                                      # label = f'time_delta_constraint={time_delta_constraint},\nlow_constraint={low_constraint}, \nhigh_constraint={high_constraint}'
                                      label = f"ichar_delta={ichar_delta}"
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


            # for retutn (exit), add state in the graph but not in work queue
            if next_state.addr == self._ret_trap:
                continue


            # add new work states with deltas to queue
            for ichar_delta, ichar_constraint, ichar_src in self._discover_ichar_deltas(next_state):
                if ichar_src is None:
                    block_addr, stmt_idx = -1, -1
                else:
                    block_addr, stmt_idx = ichar_src
                print(f"[.] Discovered a new input character {chr(ichar_delta)} ({ichar_delta}) defined at {block_addr:#x}:{stmt_idx}")
                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                # symbolic_time_counters = self._symbolize_timecounter(new_state)
                symbolic_ichar = self._symbolize_ichar(new_state)
                all_vars = set(symbolic_abstate_fields.values())
                # all_vars |= set(symbolic_time_counters.values())
                all_vars |= set(symbolic_ichar.values())
                # all_vars |= self.config_vars
                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, ichar_delta, ichar_constraint, ichar_src))



    def _discover_ichar_deltas(self, state: 'SimState') -> List[Tuple[int,claripy.ast.Base,Tuple[int,int]]]:
        """
        Discover all possible input characters that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        fixme.
        """
        if self.ichar is None:
            return []
        state = self._initialize_state(state)
        # test loop 1
        # state = self._initialize_state(self.init_state)
        ichar_deltas = self._symbolically_advance_ichar(state)
        # setup inspection points to catch where comparison happens
        constraint_source = { }
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        state.inspect.add_breakpoint('constraints', bp_0)

        next_states = self._traverse_one(state, discover=True)
        print("[D] check next states constraints")
        # detect required water delta
        steps: List[Tuple[int,claripy.ast.Base,Tuple[int,int]]] = [ ]
        for next_state in next_states:
            for delta in ichar_deltas:
                # for constraint in next_state.solver.constraints:
                #     original_constraint = constraint
                all_delta_constraints = [constraint for constraint in next_state.solver.constraints if delta.args[0] in constraint.variables]
                print(f"all_delta_constraints: {all_delta_constraints}")
                if all_delta_constraints:
                    step = next_state.solver.min(delta)

                    steps.append((
                        step,
                        all_delta_constraints,
                        constraint_source.get(all_delta_constraints[-1], None),
                    ))
                    continue

                else:
                    continue

        return steps

    def _symbolize_timecounter(self, state: 'SimState'):
        if self.software == "beremiz":
            return self._symbolize_timecounter_beremiz(state)
        elif self.software == 'arduino':
            return self._symbolize_timecounter_arduino(state)
        elif self.software == 'simulink':
            return self._symbolize_timecounter_simulink(state)
        else:
            raise ValueError(f"unknown software type for time counter: {self.software!r}")

    def _symbolize_ichar(self, state: 'SimState') -> Dict[str, claripy.ast.Base]:
        (ichar_addr, ichar_sort, ichar_size) = self.ichar_info
        prev = state.memory.load(ichar_addr, size=ichar_size, endness=self.project.arch.memory_endness)
        prev_ichar = state.solver.eval(prev)
        self.ichar = claripy.BVS('ichar', ichar_size * self.project.arch.byte_width)
        state.memory.store(ichar_addr, self.ichar, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.BVV(prev_ichar, ichar_size * self.project.arch.byte_width), self.ichar)
        return {'ichar': self.ichar}

    def _symbolically_advance_ichar(self, state: 'SimState') -> List[claripy.ast.Bits]:
        (ichar_addr, ichar_sort, ichar_size) = self.ichar_info
        ichar_delta = claripy.BVS("ichar_delta", ichar_size * self.project.arch.byte_width)
        state.memory.store(ichar_addr, ichar_delta, endness=self.project.arch.memory_endness)
        return [ichar_delta]

    def _advance_ichar(self, state: 'SimState', delta) -> None:
        (ichar_addr, ichar_sort, ichar_size) = self.ichar_info
        self.ichar = claripy.BVS('ichar', ichar_size * self.project.arch.byte_width)
        state.memory.store(ichar_addr, self.ichar, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.BVV(delta, ichar_size * self.project.arch.byte_width), self.ichar)

    def _traverse_one(self, state: 'SimState', discover: bool = False):

        simgr = self.project.factory.simgr(state)

        while simgr.active:
            simgr.step()

            # print(simgr.active)
            s = simgr.active[0]
            # print(s)
            if not discover:
                if len(simgr.active) > 1:
                    raise RuntimeError("scan cycle execution forked into multiple active states")

            # if any(x.addr == 0x4016aa for x in simgr.active):
            #     print("[D] check record type assignment")

            # return
            simgr.stash(lambda x: x.addr == self._ret_trap, from_stash='active', to_stash='finished')
            # break
            simgr.stash(lambda x: x.addr == 0x4018cb, from_stash='active', to_stash='finished')


        # import sys
        # sys.stdout.write('\n')
        if discover:
            return simgr.finished
        else:
            assert len(simgr.finished) == 1
            return simgr.finished[0]


    def _initialize_state(self, init_state=None) -> 'SimState':
        if init_state is not None:
            s = init_state.copy()
            s.ip = self.func
        else:
            s = self.project.factory.blank_state(addr=self.func)
            s.regs.rdi = 0xc0000000
            s.memory.store(0xc0000000, b"\x00" * 0x1000)

        # disable cross instruction optimization so that statement IDs in symbolic execution will match the ones used in
        # static analysis
        s.options[NO_CROSS_INSN_OPT] = True
        # disable warnings
        s.options[SYMBOL_FILL_UNCONSTRAINED_MEMORY] = True
        s.options[SYMBOL_FILL_UNCONSTRAINED_REGISTERS] = True

        if self.project.arch.call_pushes_ret:
            # s.stack_push(claripy.BVV(self._ret_trap, self.project.arch.bits))
            # for loop, point last rbp to return trap
            s.memory.store(0x7ffffffffff0000, claripy.BVV(self._ret_trap, self.project.arch.bits), endness=self.project.arch.memory_endness)
        else:
            # set up the link register for the return address
            s.regs.lr = self._ret_trap

        return s


AnalysesHub.register_default('StateGraphRecoveryIhex', StateGraphRecoveryAnalysis)
