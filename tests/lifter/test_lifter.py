import os

import networkx
import json
import claripy
import angr

from angr.sim_options import ZERO_FILL_UNCONSTRAINED_MEMORY

from . import state_graph_recovery
from taveren import (
    AbstractStateFields,
    MinDelayBaseRule,
    RuleVerifier,
    IllegalNodeBaseRule,
    MaxDelayBaseRule,
    IllegalTransitionBaseRule
)
# from angr.analyses.analysis import Analysis, AnalysesHub
# AnalysesHub.register_default('StateGraphRecovery', StateGraphRecoveryAnalysis)
# from state_graph_recovery.apis import generate_patch, apply_patch, apply_patch_on_state, EditDataPatch

import time

TEST_DIR = os.path.dirname(os.path.realpath(__file__))

# state graph acquired. define a rule
class MotorExclusionRule(IllegalNodeBaseRule):
    def verify_node(self, graph, node):
        n = dict(node)
        # The conveyor motor, lift up motor, and lift down motor cannot be on at the same time
        if (int(bool(n.get("CONVEYOR_MOTOR", 0)))
            + int(bool(n.get("LIFT_UP_MOTOR", 0)))
            + int(bool(n.get("LIFT_DOWN_MOTOR", 0)))) > 1:
            return False
        return True

class HignUpMotorOffRule(IllegalTransitionBaseRule):
    def verify_node(self, graph, src):
        # The lift up motor must be off when the rack is above assigned rack
        for dst in graph.successors(src):
            if dict(dst)["LIFT_UP_MOTOR"] > 0:    # lift up motor is on, for int type
                edges = graph.get_edge_data(src, dst)
                for edge_data in edges.values():
                    if edge_data["current_rack_delta"] is not None and  edge_data["current_rack_delta"] >= 6 :
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

def test_lifter():
    binary_path = os.path.join(TEST_DIR, '../fixtures/warehouse_lift/build/warehouse_lift.so')
    variable_path = os.path.join(TEST_DIR, 'lifter.json')
    start_time = time.time()

    proj = angr.Project(binary_path, auto_load_libs=False)
    global data
    with open(variable_path) as f:
        data = json.load(f)
    # print(data)

    # We do not support Python eval (obviously)
    cfg = proj.analyses.CFG()

    # nnode = len(list(cfg.kb.functions[0x423a54].transition_graph.nodes()))
    # print(f"number of blocks: {nnode}")
    # nedge = len(list(cfg.kb.functions[0x423a54].transition_graph.edges()))
    # print(f"number of edges: {nedge}")
    # import ipdb; ipdb.set_trace()
    _hook_py_extensions(proj, cfg)

    # run the state initializer
    init = cfg.kb.functions['config_init__']
    init_callable = proj.factory.callable(init.addr, perform_merge=False, add_options={ZERO_FILL_UNCONSTRAINED_MEMORY})
    init_callable.perform_call()
    initial_state = init_callable.result_state
    # import ipdb; ipdb.set_trace()
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

    fields_output = AbstractStateFields(outputs)
    fields_input = AbstractStateFields(inputs)
    func = cfg.kb.functions['__run']
    sgr = proj.analyses.StateGraphRecoveryLifter(func, fields_output, software, time_addr, init_state=initial_state,
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
    variant_name = os.path.basename(variable_path).replace(".json", "")
    graphs_dir = os.path.join(TEST_DIR, 'graphs')
    os.makedirs(graphs_dir, exist_ok=True)
    write_dot(sgr.state_graph, os.path.join(graphs_dir, variant_name + ".dot"))

    print("Number of nodes: %d" % state_graph.number_of_nodes())
    print("Number of edges: %d" % state_graph.number_of_edges())
    # import pickle
    # with open("lifter_sgr.pickle", "wb") as f:
    #     pickle.dump(sgr, f)
    # with open("lifter_sgr.pickle", "rb") as f:
    #     sgr = pickle.load(f)
    # state_graph = sgr.state_graph

    finder = RuleVerifier(state_graph)
    rule1_start_time = time.time()

    rule1 = MotorExclusionRule()
    r, src, dst = finder.verify(rule1)
    rule1_time = time.time()
    print("------------rule1 time: %s ----------" % (rule1_time - rule1_start_time))

    rule2 = HignUpMotorOffRule()
    r, src, dst = finder.verify(rule2)
    rule2_time = time.time()
    print("------------rule2 time: %s ----------" % (rule2_time - rule1_time))
