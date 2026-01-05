from itertools import count
from typing import Optional, List, Dict, Tuple, Set, Callable, Any, TYPE_CHECKING

import networkx
import itertools

import claripy
import pprint
from angr.sim_options import NO_CROSS_INSN_OPT, SYMBOL_FILL_UNCONSTRAINED_MEMORY, SYMBOL_FILL_UNCONSTRAINED_REGISTERS
from angr.state_plugins.inspect import BP_BEFORE, BP_AFTER, BP
from angr.analyses.analysis import Analysis, AnalysesHub

if TYPE_CHECKING:
    from angr import SimState
    from angr.knowledge_plugins.functions import Function
    from .abstract_state import AbstractStateFields


class ConstraintLogger:
    """
    Logs constraints and where they are created via the on_adding_constraints callback.
    """
    def __init__(self, mapping: Dict[claripy.ast.Base,Tuple[int,int]]):
        self.mapping = mapping

    def on_adding_constraints(self, state: 'SimState'):
        added_constraints = state._inspect_getattr('added_constraints', None)
        if not (len(added_constraints) == 1 and (
                claripy.is_true(added_constraints[0]) or
                claripy.is_false(added_constraints[0]))):
            for constraint in added_constraints:
                self.mapping[constraint] = state.scratch.irsb.addr, state.scratch.stmt_idx


class ExpressionLogger:
    """
    Logs symbolic expressions and where they are created via the on_register_write callback.
    """
    def __init__(self, mapping: Dict[claripy.ast.Base,Tuple[int,int]], variables: Set[str]):
        self.mapping = mapping
        self.variables: Set[str] = variables if variables else set()

    def on_memory_read(self, state: 'SimState'):
        expr = state._inspect_getattr("mem_read_expr", None)
        if expr is not None and expr.symbolic and expr.variables.intersection(self.variables):
            mem_read_addr = state._inspect_getattr("mem_read_address", None)
            if mem_read_addr is not None:
                if isinstance(mem_read_addr, int):
                    self.mapping[expr] = mem_read_addr
                elif not mem_read_addr.symbolic:
                    self.mapping[expr] = mem_read_addr.concrete_value

    def on_register_write(self, state: 'SimState'):
        expr = state._inspect_getattr('reg_write_expr', None)
        if expr is not None and expr.symbolic and expr.variables.intersection(self.variables):
            if expr not in self.mapping:
                # do not overwrite an existing source - it might have been from a memory read, which is the real source...
                self.mapping[expr] = state.scratch.irsb.addr, state.scratch.stmt_idx


class DefinitionNode:
    def __init__(self, variable: str, block_addr: int, stmt_idx: int):
        self.variable = variable
        self.block_addr = block_addr
        self.stmt_idx = stmt_idx

    def __eq__(self, other):
        return (
                isinstance(other, DefinitionNode)
                and self.variable == other.variable
                and self.block_addr == other.block_addr
        )

    def __hash__(self):
        return hash((DefinitionNode, self.variable, self.block_addr, self.stmt_idx))

    def __repr__(self):
        return f"{self.variable}@{self.block_addr:#x}:{self.stmt_idx}"


class SliceGenerator:
    def __init__(self, symbolic_exprs: Set[claripy.ast.Base], bp: Optional[BP]=None):
        self.bp: Optional[BP] = bp
        self.symbolic_exprs = symbolic_exprs
        self.expr_variables = set()

        # FIXME: The algorithm is hackish and incorrect. We should fix it later.
        self._last_statements = { }
        self.slice = networkx.MultiDiGraph()

        for expr in self.symbolic_exprs:
            self.expr_variables |= expr.variables

        if self.bp is not None:
            self.bp.action = self._examine_expr

    def install_expr_hook(self, state: 'SimState') -> BP:
        bp = BP(when=BP_AFTER, enabled=False, action=self._examine_expr)
        state.inspect.add_breakpoint('expr', bp)
        self.bp = bp
        return bp

    def _examine_expr(self, state: 'SimState'):
        expr = state._inspect_getattr('expr_result', None)
        if state.solver.symbolic(expr) and expr.variables.intersection(self.expr_variables):

            variables = expr.variables
            curr_loc = state.scratch.irsb.addr, state.scratch.stmt_idx
            for v in variables:
                pred = self._last_statements.get(v, None)
                if pred is not None:
                    self.slice.add_edge(DefinitionNode(v, pred[0], pred[1]),
                                        DefinitionNode(v, curr_loc[0], curr_loc[1]))
                self._last_statements[v] = curr_loc
            # print(expr, state.scratch.irsb.statements[state.scratch.stmt_idx])


class MultiDiGraph_DedupeEdge(networkx.MultiDiGraph):
    def add_edge(self, u_for_edge, v_for_edge, key=None, **attr):
        u, v = u_for_edge, v_for_edge

        # Add nodes
        if u not in self._succ:
            if u is None:
                raise ValueError("None cannot be a node")
            self._succ[u] = self.adjlist_inner_dict_factory()
            self._pred[u] = self.adjlist_inner_dict_factory()
            self._node[u] = self.node_attr_dict_factory()
        if v not in self._succ:
            if v is None:
                raise ValueError("None cannot be a node")
            self._succ[v] = self.adjlist_inner_dict_factory()
            self._pred[v] = self.adjlist_inner_dict_factory()
            self._node[v] = self.node_attr_dict_factory()

        # Dedupe logic: Check if an edge with the same u, v, and all attributes already exists
        if v in self._succ[u]:
            for existing_key, data in self._succ[u][v].items():
                for attr_key, attr_value in attr.items():
                    if "constraint" in attr_key:
                        continue
                    if data.get(attr_key) == attr_value:
                        continue
                    else:
                        break
                else:
                    # An edge with the same u, v, and all attributes already exists, do not add a new one
                    print(f"Edge ({u}, {v}, {attr}) already exists. Skipping addition.")
                    return key

        # Generate a new key if none is provided
        if key is None:
            key = self.new_edge_key(u, v)

        if v in self._succ[u]:
            # import ipdb; ipdb.set_trace()
            keydict = self._adj[u][v]
            datadict = keydict.get(key, self.edge_attr_dict_factory())
            datadict.update(attr)
            keydict[key] = datadict
        else:
            # import ipdb; ipdb.set_trace()
            # selfloops work this way without special treatment
            datadict = self.edge_attr_dict_factory()
            datadict.update(attr)
            keydict = self.edge_key_dict_factory()
            keydict[key] = datadict
            self._succ[u][v] = keydict
            self._pred[v][u] = keydict

        networkx._clear_cache(self)
        return key


class StateGraphRecoveryAnalysis(Analysis):
    """
    Traverses a function and derive a state graph with respect to given variables.
    """
    def __init__(self, func_addr: int, fields: 'AbstractStateFields', software: str,
                 time_addr: int, temp_addr: int = None,
                 init_state: Optional['SimState']=None,
                 inputs:Dict=None,
                 fields_input: Optional[Any]=None,
                 mode: str = None,
                 switch_on: Optional[Callable]=None,
                 printstate: Optional[Callable]=None,
                 config_vars: Optional[Set[claripy.ast.Base]]=None,
                 patch_callback: Optional[Callable]=None):
        self.func_addr = func_addr
        self.fields = fields
        self.config_vars = config_vars if config_vars is not None else set()
        self.software = software
        self.init_state = init_state
        self.inputs = inputs
        self.fields_input = fields_input
        self.mode = mode
        self._switch_on = switch_on
        self._ret_trap: int = 0x401EF6
        self.printstate = printstate
        self.patch_callback = patch_callback

        self._time_addr = time_addr
        self.altitude_info = inputs["altitude"]
        self.anomaly_info = inputs["anomaly"]
        self.altitude = None
        self.anomaly = None
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
        symbolic_altitude = self._symbolize_altitude(init_state)

        # setup inspection points to catch where expressions are created
        all_vars = set(symbolic_abstate_fields.values())
        all_vars |= set(symbolic_time_counters.values())
        all_vars | set(symbolic_altitude.values())
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
        state_queue = [(init_state, abs_state_id, abs_state, None, None, None, None, None, None, None, None, None, None)]

        switched_on = False if self._switch_on else True

        known_transitions = list()
        known_states = dict()
        # import ipdb; ipdb.set_trace()
        absstate_to_slice = { }
        while state_queue:
            (prev_state, prev_abs_state_id, prev_abs_state, prev_prev_abs, time_delta, time_delta_constraint, time_delta_src,
             altitude_delta, altitude_constraint, altitude_src, anomaly_delta, anomaly_constraint, anomaly_src) = state_queue.pop(0)
            print(prev_abs_state, time_delta, altitude_delta, anomaly_delta)
            # if prev_abs_state[0][1] == 1 and low_delta == 0:
            #     import ipdb; ipdb.set_trace()
            # import ipdb; ipdb.set_trace()
            if time_delta is None:
                pass
            else:
                # advance the time stamp as required
                self._advance_timecounter(prev_state, time_delta)
            if altitude_delta is not None:
                self._advance_altitude(prev_state, altitude_delta)
            if anomaly_delta is not None:
                self._advance_anomaly(prev_state, anomaly_delta)

            # symbolically trace the state
            # expression_bp.enabled = True
            next_state = self._traverse_one(prev_state)
            # print(next_state.solver.eval(next_state.memory.load(self._time_addr, 8, endness=self.project.arch.memory_endness)))

            # expression_bp.enabled = False

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
            # absstate_to_slice[abs_state] = slice_gen.slice
            # print("[.] There are %d nodes in the slice." % len(slice_gen.slice))

            transition = (prev_prev_abs, prev_abs_state, abs_state, altitude_delta)
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
                                      altitude_delta=altitude_delta,
                                      altitude_constraint=altitude_constraint,
                                      altitude_src=altitude_src,
                                      anomaly_delta=anomaly_delta,
                                        anomaly_constraint=anomaly_constraint,
                                        anomaly_src=anomaly_src,

                                      label = f"time_delta={time_delta}\naltitude_delta={altitude_delta}\nanomaly_delta={anomaly_delta}"
                                      )

            # discover time deltas
            # # also discover what other input fields are used in the constraints
            time_delta_and_sources = self._discover_time_deltas(next_state)

            for delta, constraint, source in time_delta_and_sources:
                if source is None:
                    block_addr, stmt_idx = -1, -1
                else:
                    block_addr, stmt_idx = source
                print(f"[.] Discovered a new time interval {delta} defined at {block_addr:#x}:{stmt_idx}")

                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                symbolic_time_counters = self._symbolize_timecounter(new_state)
                symbolic_altitude = self._symbolize_altitude(new_state)
                all_vars = set(symbolic_abstate_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                all_vars |= set(symbolic_altitude.values())
                all_vars |= self.config_vars
                # slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, delta, constraint, source , None, None, None, None, None, None))


            # import ipdb; ipdb.set_trace()
            # anomaly_deltas_and_sources = self._discover_anomaly_values(next_state)
            # add new work states with deltas to queue
            for altitude_delta, altitude_constraint, altitude_src in self._discover_altitude_deltas(next_state):
                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                symbolic_time_counters = self._symbolize_timecounter(new_state)
                symbolic_altitude = self._symbolize_altitude(new_state)
                symbolic_anomaly = self._symbolize_anomaly(new_state)
                all_vars = set(symbolic_abstate_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                all_vars |= set(symbolic_altitude.values())
                all_vars |= set(symbolic_anomaly.values())
                all_vars |= self.config_vars
                # slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                if self.mode == "full":
                    state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, altitude_delta+2, altitude_constraint, altitude_src, 1.0, None, None))   # add these two lines for full
                    state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, altitude_delta+2, altitude_constraint, altitude_src, 0.0, None, None))

                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, altitude_delta+2, altitude_constraint, altitude_src, None, None, None))

            if self.mode == "full":
                # add two states to the queue, add for full
                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
                symbolic_time_counters = self._symbolize_timecounter(new_state)
                symbolic_altitude = self._symbolize_altitude(new_state)
                symbolic_anomaly = self._symbolize_anomaly(new_state)
                all_vars = set(symbolic_abstate_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                all_vars |= set(symbolic_altitude.values())
                all_vars |= set(symbolic_anomaly.values())
                all_vars |= self.config_vars
                # slice_gen = SliceGenerator(all_vars, bp=expression_bp)

                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, None, None, None, 1.0, None, None))
                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, None, None, None, 0.0, None, None))



            # else:
            #     new_state = self._initialize_state(init_state=next_state)
            #
            #     # re-symbolize input fields, time counters, and update slice generator
            #     symbolic_abstate_fields = self._symbolize_var_fields(new_state, self.fields)
            #     symbolic_time_counters = self._symbolize_timecounter(new_state)
            #     symbolic_altitude = self._symbolize_altitude(new_state)
            #     all_vars = set(symbolic_abstate_fields.values())
            #     all_vars |= set(symbolic_time_counters.values())
            #     all_vars |= set(symbolic_altitude.values())
            #     all_vars |= self.config_vars
            #     slice_gen = SliceGenerator(all_vars, bp=expression_bp)
            #     state_queue.append((
            #                        new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, None, None, None))


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
        bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        state.inspect.add_breakpoint('constraints', bp_0)

        next_state = self._traverse_one(state)
        # import ipdb; ipdb.set_trace()
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
                    if delta.args[0] in constraint.variables:
                        # import ipdb; ipdb.set_trace()
                        if constraint.op in ["Not", "ULE"]:
                            leaf_ast = list(constraint.leaf_asts())
                            if len(leaf_ast) == 2:
                                concrete_leaf = [leaf for leaf in leaf_ast if leaf.op in ["BVV", "FPV"]][0]

                                # import ipdb; ipdb.set_trace()
                                step = concrete_leaf.concrete_value
                                if step > 0 and step < 14:    # simulink abort hack
                                    steps.append((
                                        step,
                                        constraint,
                                        constraint_source.get(original_constraint, None),
                                    ))

                                    break
                            elif len(leaf_ast) == 3:
                                concrete_leaves = [leaf for leaf in leaf_ast if leaf.op in ["BVV", "FPV"]]
                                step = [concrete_leaf.concrete_value for concrete_leaf in concrete_leaves if concrete_leaf.concrete_value > 1 and concrete_leaf.concrete_value < 14][0]
                                if step > 1 and step < 14:
                                    steps.append((
                                        step,
                                        constraint,
                                        constraint_source.get(original_constraint, None),
                                    ))
                                    break
                            else:
                                import ipdb; ipdb.set_trace()
                    # if constraint.op == "__eq__" and constraint.args[0] is delta:
                    #     continue
                    # elif constraint.op in ('ULE'):  # arduino arm32
                    #     if constraint.args[0].args[1] is delta:
                    #         if constraint.args[1].args[0].op == 'BVV':
                    #             step = constraint.args[1].args[0].args[0]
                    #             if step != 0:
                    #                 steps.append((
                    #                     step,
                    #                     constraint,
                    #                     constraint_source.get(original_constraint, None),
                    #                 ))
                    #                 continue
                    #
                    # elif constraint.op in ("__le__",):  # simulink arm32
                    #     if constraint.args[0].args[1] is delta:
                    #         if constraint.args[1].op == 'BVV':
                    #             step = constraint.args[1].args[0]
                    #             if step != 0 and step < 255:
                    #                 steps.append((
                    #                     step,
                    #                     constraint,
                    #                     constraint_source.get(original_constraint, None),
                    #                 ))
                    #                 continue
                    #         elif constraint.args[1].args[0].op == 'BVV':    # arduino arm32 oven
                    #             step = constraint.args[1].args[0].args[0]
                    #             if step != 0:
                    #                 steps.append((
                    #                     step,
                    #                     constraint,
                    #                     constraint_source.get(original_constraint, None),
                    #                 ))
                    #                 continue
                    # elif constraint.op == "__ne__":
                    #     if constraint.args[0] is delta:     # amd64
                    #         # found a potential step
                    #         if constraint.args[1].op == 'BVV':
                    #             step = constraint.args[1].concrete_value
                    #             if step != 0 and step < 255:
                    #                 steps.append((
                    #                     step,
                    #                     constraint,
                    #                     constraint_source.get(original_constraint, None),
                    #                 ))
                    #                 continue
                    #         else:
                    #             # attempt to evaluate the right-hand side
                    #             values = state.solver.eval_upto(constraint.args[1], 2)
                    #             if len(values) == 1:
                    #                 # it has a single value!
                    #                 step = values[0]
                    #                 if step != 0:
                    #                     steps.append((
                    #                         step,
                    #                         constraint,
                    #                         constraint_source.get(original_constraint, None),
                    #                     ))
                    #                     continue
                    #
                    #     if constraint.args[1].op == "BVS":      # arm32
                    #         # access constraint.args[1].args[2]
                    #         if constraint.args[1].args[2] is delta or constraint.args[1] is delta:
                    #             if constraint.args[0].op == 'BVV':
                    #                 step = constraint.args[0].args[0]
                    #                 if step != 0:
                    #                     steps.append((
                    #                         step,
                    #                         constraint,
                    #                         constraint_source.get(original_constraint, None),
                    #                     ))
                    #                     continue
        return steps

    def _discover_altitude_deltas(self, state: 'SimState') -> List[Tuple[int,claripy.ast.Base,Tuple[int,int]]]:
        """
        Discover all possible altitude that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """
        if self.altitude is None:
            return []
        state = self._initialize_state(state)

        altitude_deltas = self._symbolically_advance_altitude(state)
        # setup inspection points to catch where comparison happens
        constraint_source = { }
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        state.inspect.add_breakpoint('constraints', bp_0)

        next_state = self._traverse_one(state)

        # detect required water delta
        steps: List[Tuple[int,claripy.ast.Base,Tuple[int,int]]] = [ ]
        for delta in altitude_deltas:
            for constraint in next_state.solver.constraints:
                original_constraint = constraint

                if delta.args[0] in constraint.variables:
                    # import ipdb; ipdb.set_trace()
                    if constraint.op == "Or":
                        # fixme: hack
                        constraint = constraint.args[0]
                        if constraint.op in ["Not", "fpLT"]:
                            leaf_ast = list(constraint.leaf_asts())
                            if len(leaf_ast) == 2:
                                concrete_leaf = [leaf for leaf in leaf_ast if leaf.op == "FPV"][0]

                                # import ipdb; ipdb.set_trace()
                                step = concrete_leaf.concrete_value
                                steps.append((
                                    step,
                                    constraint,
                                    constraint_source.get(original_constraint, None),
                                ))

                                break

                            else:
                                import ipdb; ipdb.set_trace()


                else:
                    continue
        print(steps)


        return steps

    # def _discover_anomaly_values(self, state: 'SimState') -> List[Tuple[int,claripy.ast.Base,Tuple[int,int]]]:
    #     """
    #     Discover all possible anomaly value that may be required to transition the current state to successor states.
    #
    #     :param state:   The current initial state.
    #     :return:        A list of ints where each int represents the required interval in number of seconds.
    #     """
    #     if self.altitude is None:
    #         return []
    #     state = self._initialize_state(state)
    #
    #     anomaly_deltas = self._symbolically_advance_anomaly(state)
    #     # setup inspection points to catch where comparison happens
    #     constraint_source = { }
    #     constraint_logger = ConstraintLogger(constraint_source)
    #     bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
    #     state.inspect.add_breakpoint('constraints', bp_0)
    #
    #     next_states = self._traverse_one(state, discover=True)
    #     import ipdb; ipdb.set_trace()
        # # detect required water delta
        # steps: List[Tuple[int,claripy.ast.Base,Tuple[int,int]]] = [ ]
        # for delta in anomaly_deltas:
        #     for constraint in next_state.solver.constraints:
        #         original_constraint = constraint
        #
        #         if delta.args[0] in constraint.variables:
        #             # import ipdb; ipdb.set_trace()
        #             if constraint.op == "Or":

    def _simplify_constraint(self, constraint: claripy.ast.Base, source: Dict[claripy.ast.Base,Any]) -> Tuple[Optional[claripy.ast.Base],Dict[claripy.ast.Base,Any]]:
        """
        Attempt to simplify a constraint and generate a new source mapping.

        Note that this simplification focuses on readability and is not always sound!

        :param constraint:
        :param source:
        :return:
        """

        if (constraint.op in ("__ne__", "__eq__", "ULE")
                and constraint.args[0].op == "__add__"
                and constraint.args[1].op == "__add__"):
            # remove arguments that appear in both sides of the comparison
            same_args = set(constraint.args[0].args).intersection(set(constraint.args[1].args))
            if same_args:
                left_new_args = tuple(arg for arg in constraint.args[0].args if arg not in same_args)
                left = constraint.args[0].make_like("__add__", left_new_args) if len(left_new_args) > 1 else left_new_args[0]
                if constraint.args[0] in source:
                    source[left] = source[constraint.args[0]]

                right_new_args = tuple(arg for arg in constraint.args[1].args if arg not in same_args)
                right = constraint.args[1].make_like("__add__", right_new_args) if len(right_new_args) > 1 else right_new_args[0]
                if constraint.args[1] in source:
                    source[right] = source[constraint.args[1]]

                simplified = constraint.make_like(constraint.op, (left, right))
                if constraint in source:
                    source[simplified] = source[constraint]
                return self._simplify_constraint(simplified, source)

        # Transform signed-extension of fpToSBV() to unsigned extension
        if constraint.op == "Concat":
            args = constraint.args
            if all(arg.op == "Extract" for arg in args):
                if len(set(arg.args[2] for arg in args)) == 1:
                    if all(arg.args[0:2] in ((15,15), (31,31)) for arg in args[:-1]):
                        # found it!
                        core, source = self._simplify_constraint(args[0].args[2], source)
                        if core is None:
                            core = args[0].args[2]
                        simplified = claripy.ZeroExt(len(args) - 1, core)
                        if constraint in source:
                            source[simplified] = source[constraint]
                        return simplified, source
            elif all(arg.op == "Extract" for arg in args[:-1]):
                if len(set(arg.args[2] for arg in args[:-1])) == 1:
                    v = args[0].args[2]
                    if v is args[-1]:
                        if all(arg.args[0:2] in ((15,15), (31,31)) for arg in args[:-1]):
                            # found it!
                            core, source = self._simplify_constraint(v, source)
                            if core is None:
                                core = v
                            simplified = claripy.ZeroExt(len(args) - 1, core)
                            if constraint is source:
                                source[simplified] = source[constraint]
                            return simplified, source

        elif constraint.op in ('__ne__', '__mod__', '__floordiv__'):
            left, source = self._simplify_constraint(constraint.args[0], source)
            right, source = self._simplify_constraint(constraint.args[1], source)
            if left is None and right is None:
                return None, source
            if left is None:
                left = constraint.args[0]
            if right is None:
                right = constraint.args[1]
            simplified = constraint.make_like(constraint.op, (left, right))
            if constraint in source:
                source[simplified] = source[constraint]
            return simplified, source

        elif constraint.op in ('__add__', ):
            new_args = [ ]
            simplified = False
            for arg in constraint.args:
                new_arg, source = self._simplify_constraint(arg, source)
                if new_arg is not None:
                    new_args.append(new_arg)
                    simplified = True
                else:
                    new_args.append(arg)
            if not simplified:
                return None, source
            simplified = constraint.make_like(constraint.op, tuple(new_args))
            if constraint in source:
                source[simplified] = source[constraint]
            return simplified, source

        elif constraint.op in ('fpToSBV', 'fpToFP'):
            arg1, source = self._simplify_constraint(constraint.args[1], source)
            if arg1 is None:
                return None, source
            simplified = constraint.make_like(constraint.op, (constraint.args[0], arg1, constraint.args[2]))
            if constraint in source:
                source[simplified] = source[constraint]
            return simplified, source

        elif constraint.op in ('fpMul', ):
            if constraint.args[1].op == "FPV" and constraint.args[1].concrete_value == 0.0:
                return constraint.args[1], source
            elif constraint.args[2].op == "FPV" and constraint.args[2].concrete_value == 0.0:
                return constraint.args[2], source
            arg1, source = self._simplify_constraint(constraint.args[1], source)
            arg2, source = self._simplify_constraint(constraint.args[2], source)
            if arg1 is None and arg2 is None:
                return None, source
            if arg1 is None:
                arg1 = constraint.args[1]
            if arg2 is None:
                arg2 = constraint.args[2]
            simplified = constraint.make_like(constraint.op, (constraint.args[0], arg1, arg2))
            if constraint in source:
                source[simplified] = source[constraint]
            return simplified, source

        return None, source

    def _symbolize_var_fields(self, state: 'SimState', fields) -> Dict[str,claripy.ast.Base]:

        symbolic_input_vars = { }

        for name, (address, type_, size) in fields.fields.items():
            # print(f"[.] Symbolizing field {name}...")

            v = state.memory.load(address, size=size, endness=self.project.arch.memory_endness)
            if not state.solver.symbolic(v):
                # if type_ == "float":
                #     concrete_v = state.solver.eval(v, cast_to=float)
                #     symbolic_v = claripy.FPS(name, claripy.fp.FSORT_FLOAT)
                # elif type_ == "double":
                #     concrete_v = state.solver.eval(v, cast_to=float)
                #     symbolic_v = claripy.FPS(name, claripy.fp.FSORT_DOUBLE)
                # else:
                concrete_v = state.solver.eval(v)
                symbolic_v = claripy.BVS(name, size * self.project.arch.byte_width)
                symbolic_input_vars[name] = symbolic_v

                # update the value in memory
                state.memory.store(address, symbolic_v, endness=self.project.arch.memory_endness)

                # preconstrain it
                state.preconstrainer.preconstrain(concrete_v, symbolic_v)
            else:
                symbolic_input_vars[name] = v

        return symbolic_input_vars

    def _symbolize_timecounter(self, state: 'SimState') -> Dict[str,claripy.ast.Base]:
        if self.software == "beremiz":
            return self._symbolize_timecounter_beremiz(state)
        elif self.software == 'arduino':
            return self._symbolize_timecounter_arduino(state)
        elif self.software == 'simulink':
            return self._symbolize_timecounter_simulink(state)

    # simulink time 255
    def _symbolize_timecounter_simulink(self, state: 'SimState') -> Dict[str,claripy.ast.Base]:
        tv_sec_addr = self._time_addr
        # prev = state.memory.load(self._time_addr, size=1, endness=self.project.arch.memory_endness)
        # prev_time = state.solver.eval(prev) + 1

        self._tv_sec_var = claripy.BVS('tv_sec', 1 * self.project.arch.byte_width)
        state.memory.store(tv_sec_addr, self._tv_sec_var, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(
            claripy.BVV(0, 1 * self.project.arch.byte_width), self._tv_sec_var)

        return {'tv_sec': self._tv_sec_var}

    # Traffic_Light Beremiz
    def _symbolize_timecounter_beremiz(self, state: 'SimState') -> Dict[str,claripy.ast.Base]:
        tv_sec_addr = self._time_addr
        tv_nsec_addr = tv_sec_addr + self.project.arch.bytes

        self._tv_sec_var = claripy.BVS('tv_sec', self.project.arch.bytes * self.project.arch.byte_width)
        # self._tv_nsec_var = claripy.BVS('tv_nsec', self.project.arch.bytes * self.project.arch.byte_width)
        self._tv_nsec_var = claripy.BVV(1, self.project.arch.bytes * self.project.arch.byte_width)

        state.memory.store(tv_sec_addr, self._tv_sec_var, endness=self.project.arch.memory_endness)
        state.memory.store(tv_nsec_addr, self._tv_nsec_var, endness=self.project.arch.memory_endness)

        # the initial timer values are 0
        state.preconstrainer.preconstrain(claripy.BVV(0, self.project.arch.bytes * self.project.arch.byte_width), self._tv_sec_var)
        # state.preconstrainer.preconstrain(claripy.BVV(0, self.project.arch.bytes * self.project.arch.byte_width), self._tv_nsec_var)

        return {
            'tv_sec_var': self._tv_sec_var
        }

    # reflowoven Arduino
    def _symbolize_timecounter_arduino(self, state: 'SimState') -> Dict[str, claripy.ast.Base]:
        tv_sec_addr = self._time_addr
        prev = state.memory.load(self._time_addr, size=self.project.arch.bytes, endness=self.project.arch.memory_endness)
        prev_time = state.solver.eval(prev) + 1

        self._tv_sec_var = claripy.BVS('tv_sec', self.project.arch.bytes * self.project.arch.byte_width)
        state.memory.store(tv_sec_addr, self._tv_sec_var, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.BVV(prev_time, self.project.arch.bytes * self.project.arch.byte_width), self._tv_sec_var)

        return {'tv_sec': self._tv_sec_var}

    def _symbolically_advance_timecounter(self, state: 'SimState') -> List[claripy.ast.Bits]:
        bytesize = self.project.arch.bytes
        if self.software == 'simulink':
            bytesize = 1
        sec_delta = claripy.BVS("sec_delta", bytesize * self.project.arch.byte_width)
        state.preconstrainer.preconstrain(claripy.BVV(1, bytesize * self.project.arch.byte_width), sec_delta)

        tv_sec = state.memory.load(self._time_addr, size=bytesize, endness=self.project.arch.memory_endness)
        state.memory.store(self._time_addr, sec_delta, endness=self.project.arch.memory_endness)

        return [sec_delta]

    def _advance_timecounter(self, state: 'SimState', delta: int) -> None:
        bytesize = self.project.arch.bytes
        if self.software == 'simulink':
            bytesize = 1
        prev = state.memory.load(self._time_addr, size=bytesize, endness=self.project.arch.memory_endness)
        state.memory.store(self._time_addr, prev + delta, endness=self.project.arch.memory_endness)

        if self.software == 'beremiz':
            tv_nsec = state.memory.load(self._time_addr + self.project.arch.bytes, size=self.project.arch.bytes,
                                        endness=self.project.arch.memory_endness)
            state.memory.store(self._time_addr + self.project.arch.bytes, tv_nsec + 200,
                               endness=self.project.arch.memory_endness)

    def _symbolize_altitude(self, state: 'SimState') -> Dict[str, claripy.ast.Base]:
        (altitude_addr, altitude_sort, altitude_size) = self.altitude_info
        prev = state.memory.load(altitude_addr, size=altitude_size, endness=self.project.arch.memory_endness)
        # import ipdb; ipdb.set_trace()
        prev_altitude = state.solver.eval(prev)
        self.altitude = claripy.FPS('altitude', claripy.fp.FSORT_DOUBLE)
        state.memory.store(altitude_addr, self.altitude, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.FPV(prev_altitude, claripy.fp.FSORT_DOUBLE), self.altitude)
        return {'altitude': self.altitude}

    def _symbolically_advance_altitude(self, state: 'SimState') -> List[claripy.ast.Bits]:
        (altitude_addr, altitude_sort, altitude_size) = self.altitude_info

        altitude_delta = claripy.FPS("altitude_delta", claripy.fp.FSORT_DOUBLE)

        prev = state.memory.load(altitude_addr, size=8, endness=self.project.arch.memory_endness).raw_to_fp()
        prev_altitude = state.solver.eval(prev)
        state.preconstrainer.preconstrain(claripy.FPV(prev_altitude + 0.5, claripy.fp.FSORT_DOUBLE), altitude_delta)
        state.memory.store(altitude_addr, altitude_delta, endness=self.project.arch.memory_endness)
        return [altitude_delta]

    def _advance_altitude(self, state: 'SimState', delta) -> None:
        (altitude_addr, altitude_sort, altitude_size) = self.altitude_info
        self.altitude = claripy.FPS('altitude', claripy.fp.FSORT_DOUBLE)
        state.memory.store(altitude_addr, self.altitude, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.FPV(delta, claripy.fp.FSORT_DOUBLE), self.altitude)

    def _symbolize_anomaly(self, state: 'SimState') -> Dict[str, claripy.ast.Base]:
        (anomaly_addr, anomaly_sort, anomaly_size) = self.anomaly_info
        prev = state.memory.load(anomaly_addr, size=anomaly_size, endness=self.project.arch.memory_endness)
        prev_anomaly = state.solver.eval(prev)
        self.anomaly = claripy.FPS('anomaly', claripy.fp.FSORT_DOUBLE)
        state.memory.store(anomaly_addr, self.anomaly, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.FPV(prev_anomaly, claripy.fp.FSORT_DOUBLE), self.anomaly)
        return {'anomaly': self.anomaly}

    def _symbolically_advance_anomaly(self, state: 'SimState') -> List[claripy.ast.Bits]:
        (anomaly_addr, anomaly_sort, anomaly_size) = self.anomaly_info
        anomaly_delta = claripy.FPS("anomaly_delta", claripy.fp.FSORT_DOUBLE)
        state.memory.store(anomaly_addr, anomaly_delta, endness=self.project.arch.memory_endness)
        return [anomaly_delta]

    def _advance_anomaly(self, state: 'SimState', delta) -> None:
        (anomaly_addr, anomaly_sort, anomaly_size) = self.anomaly_info
        self.anomaly = claripy.FPS('anomaly', claripy.fp.FSORT_DOUBLE)
        state.memory.store(anomaly_addr, self.anomaly, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.FPV(delta, claripy.fp.FSORT_DOUBLE), self.anomaly)




    def _traverse_one(self, state: 'SimState', discover: bool = False):

        simgr = self.project.factory.simgr(state)

        while simgr.active:
            # print(simgr.active)
            s = simgr.active[0]
            # print(s)
            if not discover:
                if len(simgr.active) > 1:
                    import ipdb; ipdb.set_trace()

            if s.addr == 0x40160D:
                print("is_abort in Normal!!!!!!!!!!!!!")
            if s.addr == 0x40182B:
                print("check anomaly!!!!!!!!!!!!!!!!!")
            if s.addr == 0x40183B:
                print("change to abort logic!!!!!!!!!!!!!!!!")

            simgr.stash(lambda x: x.addr == self._ret_trap, from_stash='active', to_stash='finished')

            simgr.step()

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
            s.ip = self.func_addr
        else:
            s = self.project.factory.blank_state(addr=self.func_addr)
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


AnalysesHub.register_default('StateGraphRecovery', StateGraphRecoveryAnalysis)
