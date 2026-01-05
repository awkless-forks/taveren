import os
import struct
from typing import TYPE_CHECKING, Generator, Any, Iterable, Tuple, List

import networkx
import sys
import json
import claripy
import angr

sys.path.append("../")
import state_graph_recovery
from state_graph_recovery import MinDelayBaseRule, RuleVerifier, IllegalNodeBaseRule, IllegalTransitionBaseRule, MaxDelayBaseRule, BaseRule
# from angr.analyses.analysis import Analysis, AnalysesHub
# AnalysesHub.register_default('StateGraphRecovery', StateGraphRecoveryAnalysis)
# from state_graph_recovery.apis import generate_patch, apply_patch, apply_patch_on_state, EditDataPatch

if TYPE_CHECKING:
    import networkx

import time

binaries_base = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries')


# state graph acquired. define a rule
class SensorExclusionRule(BaseRule):

    def eval(self, graph: 'networkx.DiGraph') -> Tuple[bool, Any, Any]:
        for (src, dst) in graph.edges():
            for edge_data in graph.get_edge_data(src, dst).values():
                # here None can be true or false, since we are checking here is both sensors can be true, we consider None as true
                low = edge_data['low_delta'] if edge_data['low_delta'] is not None else 1
                high = edge_data['high_delta'] if edge_data['high_delta'] is not None else 1
                if low > 0 and high > 0:
                    print(edge_data)
                    return False, src, dst
        return True, None, None

class WaterHighPumpOff(IllegalTransitionBaseRule):
    def verify_node(self, graph: 'networkx.DiGraph', node: Any) -> Tuple[bool, Any]:
        for dst in graph.successors(node):
            if dict(dst)["PUMP"] == 1:
                for edge_data in graph.get_edge_data(node, dst).values():
                    if edge_data["high_delta"] is None or edge_data["high_delta"] > 0:
                        return False, dst
        return True, None


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
        if variable['type'] == 'output':
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

def generate_field_desc(var_info):
    # define abstract fields
    fields_output = {}
    fields_input = {}
    var_base_addr = var_info["variable_base_addr"]
    for variable in var_info['variables']:
        addr = var_base_addr + variable['address'] if isinstance(var_base_addr, int) else int(var_base_addr, 16) + int(
            variable['address'], 16)
        if "output" in variable["type"] or "statevar" in variable["type"]:
            fields_output[variable['name']] = (addr,
                                             variable['sort'],
                                             variable['size'],
                                             )
        if "input" in variable["type"]:
            fields_input[variable['name']] = (addr,
                                               variable['sort'],
                                               variable['size'],
                                               )

    return fields_output, fields_input

def test_water_tank(mode:str):
    if mode == 'WT1':
        binary_path = '../../artifacts/water_tank/build/water_tank.so'    # WT.1
        variable_path = 'water_tank.json'
    elif mode == 'WT3':
        binary_path = "../../artifacts/water_tank_sfc_two_sesnors/build/water_tank_sfc_two_sesnors.so"  # WT.3
        variable_path = "water_tank_sfc_twosensors.json"
    else:
        print("ERROR: unknown mode")
        return

    start_time = time.time()

    proj = angr.Project(binary_path, auto_load_libs=False)
    global data
    with open(variable_path) as f:
        data = json.load(f)
    # print(data)

    # We do not support Python eval (obviously)
    cfg = proj.analyses.CFG()

    # nnode = len(list(cfg.kb.functions[0x42c034].blocks))
    # print(f"number of blocks: {nnode}")
    # import ipdb; ipdb.set_trace()

    # for node in body_cfg.nodes():
    #     body_cfg.nodes[node]["label"] = next(id_ctr)
    #     body_cfg.nodes[node]["fontcolor"] = "white"
    # _hook_py_extensions(proj, cfg)

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
    # fields_desc, config_fields = _generate_field_desc(data, base_addr)
    outputs, inputs = generate_field_desc(data)
    # pre-constrain configuration variables so that we can track them
    # config_vars = {}
    # symbolic_config_var_to_fields = {}
    # for var_name, (var_addr, var_type, var_size) in config_fields.items():
    #     print("[.] Preconstraining %s..." % var_name)
    #     # if var_type == "float":
    #     #     symbolic_v = claripy.FPS(var_name, claripy.fp.FSORT_FLOAT)
    #     # elif var_type == "double":
    #     #     symbolic_v = claripy.FPS(var_name, claripy.fp.FSORT_DOUBLE)
    #     # else:
    #     symbolic_v = claripy.BVS(var_name, var_size * 8)
    #     concrete_v = initial_state.memory.load(var_addr, size=var_size, endness=proj.arch.memory_endness)
    #     initial_state.memory.store(var_addr, symbolic_v, endness=proj.arch.memory_endness)
    #     initial_state.preconstrainer.preconstrain(concrete_v, symbolic_v)
    #     config_vars[var_name] = symbolic_v
    #     symbolic_config_var_to_fields[symbolic_v] = var_name, var_addr, var_type, var_size

    fields_output = state_graph_recovery.AbstractStateFields(outputs)
    fields_input = state_graph_recovery.AbstractStateFields(inputs)
    func = cfg.kb.functions['RES0_run__']
    sgr = proj.analyses.StateGraphRecovery(func, fields_output, software, time_addr, init_state=initial_state,
                                        inputs = inputs, fields_input=fields_input
                                           )
    sgr_time = time.time()
    print("------------sgr time: %s ----------" % (sgr_time - init_time))
    state_graph = sgr.state_graph
    # import ipdb; ipdb.set_trace()
    # import pickle
    # pickle.dumps(sgr, -1)

    # output the graph to a dot file
    from networkx.drawing.nx_agraph import write_dot
    if mode == 'WT1':
        write_dot(sgr.state_graph, "./graphs/water_tank_fbd_two_sensors-1.dot")
    elif mode == 'WT3':
        write_dot(sgr.state_graph, "./graphs/water_tank_sfc_two_sesnors-3.dot")
    print("Number of nodes: %d" % state_graph.number_of_nodes())
    print("Number of edges: %d" % state_graph.number_of_edges())

    finder = RuleVerifier(state_graph)
    rule_start_time = time.time()

    rule = SensorExclusionRule()
    r, src, dst = finder.verify(rule)
    # assert r is True

    rule1_time = time.time()
    print("------------rule1 time: %s ----------" % (rule1_time - rule_start_time))

    # import ipdb; ipdb.set_trace()
    rule2 = WaterHighPumpOff()
    r, src, dst = finder.verify(rule2)
    # assert r is False
    rule2_time = time.time()
    print("------------rule2 time: %s ----------" % (rule2_time - rule1_time))



if __name__ == "__main__":
    mode = sys.argv[1]
    test_water_tank(mode)
