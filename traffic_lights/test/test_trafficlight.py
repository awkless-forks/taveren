import os
import struct
from typing import TYPE_CHECKING

import networkx
import sys
import json
import claripy
import angr
sys.path.append("../")
import state_graph_recovery
from state_graph_recovery import MinDelayBaseRule, RuleVerifier, IllegalNodeBaseRule, MaxDelayBaseRule
# from angr.analyses.state_graph_recovery.apis import generate_patch, apply_patch, apply_patch_on_state, EditDataPatch

if TYPE_CHECKING:
    import networkx

import time


# state graph acquired. define a rule
class MinDelayRule_PedGreen(MinDelayBaseRule):
    def node_a(self, graph: 'networkx.DiGraph'):
        # ped light is green
        for node in graph.nodes():
            sucs = list(graph.successors(node))
            if len(sucs) == 1 and graph.get_edge_data(node, sucs[0])['time_delta'] is None:
                # ignore all about-to-change states
                continue
            if dict(node)['PEDESTRIAN_GREEN_LIGHT'] == 1 and dict(node)['PEDESTRIAN_RED_LIGHT'] == 0:
                yield node

    def node_b(self, graph: 'networkx.DiGraph', start: tuple):
        # ped light is red
        visited = [start]
        queue = [start]
        while queue:
            node = queue.pop(0)
            if dict(node)['PEDESTRIAN_GREEN_LIGHT'] == 0 and dict(node)['PEDESTRIAN_RED_LIGHT'] == 1:
                yield node
                continue
            for suc in graph.successors(node):
                if suc not in visited:
                    visited.append(suc)
                    queue.append(suc)


class MinDelayRule_Orange(MinDelayBaseRule):
    def node_a(self, graph: 'networkx.DiGraph'):
        # car light is orange
        for node in graph.nodes():
            sucs = list(graph.successors(node))
            if len(sucs) == 1 and graph.get_edge_data(node, sucs[0])['time_delta'] is None:
                # ignore all about-to-change states
                continue
            if dict(node)['ORANGE_LIGHT'] == 1 and dict(node)['RED_LIGHT'] == 0:
                yield node

    def node_b(self, graph: 'networkx.DiGraph', start: tuple):
        # car light is red
        visited = [start]
        queue = [start]
        while queue:
            node = queue.pop(0)
            if dict(node)['ORANGE_LIGHT'] == 0 and dict(node)['RED_LIGHT'] == 1:
                yield node
            for suc in graph.successors(node):
                if suc not in visited:
                    visited.append(suc)
                    queue.append(suc)




class NoPedGreenCarGreen(IllegalNodeBaseRule):
    def verify_node(self, graph: 'networkx.DiGraph', node) -> bool:
        if dict(node)['GREEN_LIGHT'] == 1 and dict(node)['PEDESTRIAN_GREEN_LIGHT'] == 1:
            # both car green light and the pedestrian green light are on at the same time
            # this is bad!
            return False
        return True


def printstate(abs_state):
    # delayed import
    try:
        from termcolor import colored, cprint
    except ImportError:
        def colored(x, _): return x

    light_on = '\u25cf'
    light_off = '\u25cb'
    switch_on = u"\U0001F532"
    switch_off = u"\U0001F533"

    SWITCH_BUTTON = switch_off
    RED_LIGHT = light_off
    ORANGE_LIGHT = light_off
    GREEN_LIGHT = light_off
    PEDESTRIAN_RED_LIGHT = light_off
    PEDESTRIAN_GREEN_LIGHT = light_off

    for state in abs_state:
        if state[0] == "SWITCH_BUTTON":
            if state[1] == 1:
                SWITCH_BUTTON = switch_on
        elif state[0] == "RED_LIGHT":
            if state[1] == 1:
                RED_LIGHT = light_on
        elif state[0] == "ORANGE_LIGHT":
            if state[1] == 1:
                ORANGE_LIGHT = light_on
        elif state[0] == "GREEN_LIGHT":
            if state[1] == 1:
                GREEN_LIGHT = light_on
        elif state[0] == "PEDESTRIAN_RED_LIGHT":
            if state[1] == 1:
                PEDESTRIAN_RED_LIGHT = light_on
        elif state[0] == "PEDESTRIAN_GREEN_LIGHT":
            if state[1] == 1:
                PEDESTRIAN_GREEN_LIGHT = light_on
        else:
            print(state)

    print("SWITCH BUTTON  ", SWITCH_BUTTON)
    print("CAR LIGHTS     ", colored(RED_LIGHT, 'red'), colored(ORANGE_LIGHT, 'yellow'), colored(GREEN_LIGHT, 'green'))
    print("PED LIGHTS     ", colored(PEDESTRIAN_RED_LIGHT, 'red'), colored(PEDESTRIAN_GREEN_LIGHT, 'green'))

def switch_on(state):
    # switch on
    base_addr = int(data['variable_base_addr'], 16)
    switch = next(x for x in data['variables'] if x['name'] == "SWITCH_BUTTON")
    switch_value_addr = base_addr + int(switch['address'], 16)
    switch_flag_addr = switch_value_addr + 1
    state.memory.store(switch_value_addr, claripy.BVV(0x1, 8), endness=state.memory.endness)  # value
    state.memory.store(switch_flag_addr, claripy.BVV(0x2, 8), endness=state.memory.endness)  # flag

def _hook_py_extensions(proj, cfg):
    proj.hook(cfg.kb.functions['PYTHON_EVAL_body__'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['PYTHON_POLL_body__'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['__publish_debug'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['__publish_py_ext'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())


def _generate_field_desc(data, base_addr: int):
    # define abstract fields
    fields_desc = {}
    config_fields = {}
    for variable in data['variables']:
        if variable['type'] == 'output' or variable['type'] == 'statevar':
            fields_desc[variable['name']] = (base_addr + int(variable['address'], 16),
                                             variable.get('sort', "int"),
                                             variable['size'],
                                             )
        elif variable['type'] == 'config':
            config_fields[variable['name']] = (base_addr + int(variable['address'], 16),
                                               variable.get('sort', "int"),
                                               variable['size'],
                                               )

    return fields_desc, config_fields


def test_find_violations(mode:str):

    match mode:
        case "4":
            binary_path = '../../artifacts/traffic_light_addsensor_x86-64/Traffic_Light_addsensor_x86-64.so'    #T4   0x42C83D
            variable_path = 'traffic_light_addsensor_x86-64.json'
        case "5":
            binary_path = '../../artifacts/Traffic_Light_Short_Ped_5/build/Traffic_Light_Short_Ped.so'    # T5  0x42BF53
            variable_path = 'Traffic_Light_Short_Ped_5.json'
        case "6":
            binary_path = '../../artifacts/Traffic_Light_Short_Ped_6/build/Traffic_Light_Short_Ped.so'   #T6   0x42C698
            variable_path = 'Traffic_Light_variables_arm.json'
        case "7":
            binary_path = '../../artifacts/Traffic_Light_both_green_7/build/Traffic_Light_both_green.so'   #t7   0x42BF53
            variable_path = 'Traffic_Light_variables.json'
        case "8":
            binary_path = '../../artifacts/Traffic_Light_short_orange/build/Traffic_Light_short_orange.so'   #T8   0x42BF53
            variable_path = 'shortorange.json'
        case "9":
            binary_path = '../../artifacts/Traffic_Light_original/build/Traffic_Light_original.so'   #T9   0x42C034
            variable_path = 'original.json'
        case "10":
            binary_path = '../../artifacts/Traffic_Light_10/build/Traffic_Light.so'    #t10  0x42C698
            variable_path = 'Traffic_Light_variables_arm.json'
        case _:
            print("unknown mode")
            return


    # binary_path = sys.argv[1]
    # variable_path = sys.argv[2]

    start_time = time.time()

    proj = angr.Project(binary_path, auto_load_libs=False)
    global data
    with open(variable_path) as f:
        data = json.load(f)
    # print(data)

    # We do not support Python eval (obviously)
    cfg = proj.analyses.CFG()
    #
    # nnode = len(list(cfg.kb.functions[0x42BF53].transition_graph.nodes()))
    # print(f"number of blocks: {nnode}")
    # nedge = len(list(cfg.kb.functions[0x42BF53].transition_graph.edges()))
    # print(f"number of edges: {nedge}")
    # import ipdb; ipdb.set_trace()
    _hook_py_extensions(proj, cfg)

    # run the state initializer
    init = cfg.kb.functions['config_init__']
    init_callable = proj.factory.callable(init.addr, perform_merge=False)
    init_callable.perform_call()
    initial_state = init_callable.result_state

    assert initial_state is not None
    init_time = time.time()
    print("------------init time: %s ----------" % (init_time - start_time))

    base_addr = int(data['variable_base_addr'], 16)
    time_addr = int(data['time_addr'], 16)
    software = data['software']

    # def switch_on(state):
    #     # switch on
    # switch = next(x for x in data['variables'] if x['name'] == "SWITCH_BUTTON")
    # switch_value_addr = base_addr + int(switch['address'], 16)
    #     switch_flag_addr = switch_value_addr + 1
    #     initial_state.memory.store(switch_value_addr, claripy.BVV(0x1, 8), endness=proj.arch.memory_endness)  # value
    #     initial_state.memory.store(switch_flag_addr, claripy.BVV(0x2, 8), endness=proj.arch.memory_endness)  # flag

    # define abstract fields
    fields_desc, config_fields = _generate_field_desc(data, base_addr)

    # pre-constrain configuration variables so that we can track them
    config_vars = {}
    symbolic_config_var_to_fields = {}
    for var_name, (var_addr, var_type, var_size) in config_fields.items():
        print("[.] Preconstraining %s..." % var_name)
        # if var_type == "float":
        #     symbolic_v = claripy.FPS(var_name, claripy.fp.FSORT_FLOAT)
        # elif var_type == "double":
        #     symbolic_v = claripy.FPS(var_name, claripy.fp.FSORT_DOUBLE)
        # else:
        symbolic_v = claripy.BVS(var_name, var_size * 8)
        concrete_v = initial_state.memory.load(var_addr, size=var_size, endness=proj.arch.memory_endness)
        initial_state.memory.store(var_addr, symbolic_v, endness=proj.arch.memory_endness)
        initial_state.preconstrainer.preconstrain(concrete_v, symbolic_v)
        config_vars[var_name] = symbolic_v
        symbolic_config_var_to_fields[symbolic_v] = var_name, var_addr, var_type, var_size

    fields = state_graph_recovery.AbstractStateFields(fields_desc)
    func = cfg.kb.functions['TRAFFIC_LIGHT_SEQUENCE_body__']
    sgr = proj.analyses.StateGraphRecovery(func, fields, software, time_addr, init_state=initial_state, switch_on=switch_on,
                                           config_vars=set(config_vars.values()), printstate=printstate, arg0_addr=base_addr)
    sgr_time = time.time()
    print("------------sgr time: %s ----------" % (sgr_time - init_time))
    state_graph = sgr.state_graph

    # import pickle
    # with open("graphs/TL.5.pkl", "wb") as f:
    #     pickle.dump(state_graph, f)

    # output the graph to a dot file
    from networkx.drawing.nx_agraph import write_dot
    write_dot(sgr.state_graph, f"graphs/tl{mode}.dot")
    print("node number: ", state_graph.number_of_nodes())
    print("edge number: ", state_graph.number_of_edges())
    # import ipdb; ipdb.set_trace()
    finder = RuleVerifier(state_graph)
    rule_start_time = time.time()

    rule = MinDelayRule_Orange(2.0)
    r, src, dst = finder.verify(rule)
    # assert r is True

    rule1_time = time.time()
    print("------------rule1 time: %s ----------" % (rule1_time - rule_start_time))


    # import ipdb; ipdb.set_trace()
    rule = MinDelayRule_PedGreen(40.0)
    r, src, dst = finder.verify(rule)
    # assert r is False
    rule2_time = time.time()
    print("------------rule2 time: %s ----------" % (rule2_time - rule1_time))

    rul3start = time.time()
    rule = NoPedGreenCarGreen()
    r, src, dst = finder.verify(rule)
    # assert r is True
    rule3_time = time.time()
    print("------------rule3 time: %s ----------" % (rule3_time - rul3start))

    return

    import node_collapse
    compress_graph = node_collapse.compress_graph(state_graph, fields_desc)
    write_dot(compress_graph, "graphs/bothgreenTL.7.compressed.dot")
    import ipdb; ipdb.set_trace()

    import T7_REF
    ged = networkx.graph_edit_distance(T7_REF.T7_REF, state_graph, timeout=1000)
    print("GED = ", ged)
    print(f"[INFO] node number in Gref: {T7_REF.T7_REF.number_of_nodes()}, in Ggen: {state_graph.number_of_nodes()}")
    print(f"[INFO] edge number in Gref: {T7_REF.T7_REF.number_of_edges()}, in Ggen: {state_graph.number_of_edges()}")
    # print(f"[INFO] node number in Gref: {test_t9_gt.T9_REF.number_of_nodes()}, in Ggen: {state_graph.number_of_nodes()}")
    # print(f"[INFO] edge number in Gref: {test_t9_gt.T9_REF.number_of_edges()}, in Ggen: {state_graph.number_of_edges()}")
    import graph_cmp
    # result_optimal = networkx.optimal_edit_paths(T7_REF, state_graph, node_match=graph_cmp.node_match,
    #                                              edge_match=graph_cmp.edge_match)
    # result_optimal = networkx.optimal_edit_paths(T7_REF, state_graph)

    node0 = [node for node in sgr.state_graph.nodes() if dict(node)["NODE_CTR"] == 0][0]
    result_optimize = networkx.optimize_edit_paths(T7_REF.T7_REF, sgr.state_graph, node_match=graph_cmp.node_match, edge_match=graph_cmp.edge_match,
                                          strictly_decreasing=False, roots = ( T7_REF.node_init, node0), timeout=20000)

    # (edit_path, cost) = result_optimal

    result_list = list(result_optimize)

    print(f"cost = {result_list[-1][2]}")
    import ipdb; ipdb.set_trace()

    good_result = [path for path in result_list if path[2] == ged]
    for each_path in good_result:
        print('---------------------')
        graph_cmp.match_rate(T7_REF.T7_REF, state_graph, (each_path[0], each_path[1]))

    import ipdb; ipdb.set_trace()




if __name__ == "__main__":
    mode = sys.argv[1]
    test_find_violations(mode)
