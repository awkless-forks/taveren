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
# from angr.analyses.analysis import Analysis, AnalysesHub
# AnalysesHub.register_default('StateGraphRecovery', StateGraphRecoveryAnalysis)
# from state_graph_recovery.apis import generate_patch, apply_patch, apply_patch_on_state, EditDataPatch

from angr.sim_options import ZERO_FILL_UNCONSTRAINED_MEMORY

if TYPE_CHECKING:
    import networkx

import time

binaries_base = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries')

class normalize_timespec(angr.SimProcedure):
    def run(self):
        # print("in normalize_timespec")
        # import ipdb; ipdb.set_trace()
        return None

# state graph acquired. define a rule
# conveyor belt and product valve cannot be true at the same time
class NoBothOnRule(IllegalNodeBaseRule):
    def verify_node(self, graph: 'networkx.DiGraph', node: 'networkx.Node') -> bool:
        if dict(node)['CONVEYOR_MOTOR'] == 1 and dict(node)['PRODUCT_VALVE'] == 1:
            return False
        return True

# valve not activated more than 15 seconds
class ValveMax15s(MaxDelayBaseRule):
    def node_a(self, graph: 'networkx.DiGraph'):
        for node in graph.nodes():
            if dict(node)['PRODUCT_VALVE'] == 1:
                yield node

    def node_b(self, graph: 'networkx.DiGraph', start: tuple) :
        visited = [start]
        queue = [start]
        while queue:
            node = queue.pop(0)
            if dict(node)['PRODUCT_VALVE'] == 0:
                yield node
                continue
            for suc in graph.successors(node):
                if suc not in visited:
                    visited.append(suc)
                    queue.append(suc)



def switch_on(state):
    # switch on
    base_addr = int(data['variable_base_addr'], 16)
    switch = next(x for x in data['variables'] if x['name'] == "START_BUTTON")
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


def test_packaging(mode:str):
    match mode:
        case "x86":
            binary_path = '/home/bonnie/SMCheck/fbd_examples/packaging_sfc/build/packaging_sfc.so'
            variable_path = '/home/bonnie/SMCheck/packaging/test/packaging.json'
        case "mips":
            binary_path = "/home/bonnie/SMCheck/fbd_examples/packaging_sfc/build/packaging_sfc_mips.so"
            variable_path = "/home/bonnie/SMCheck/packaging/test/packaging_mips.json"
        case "ppc":
            binary_path = "/home/bonnie/SMCheck/fbd_examples/packaging_sfc/build/packaging_sfc_powerpc.so"
            variable_path = "/home/bonnie/SMCheck/packaging/test/packaging_ppc.json"


    start_time = time.time()

    proj = angr.Project(binary_path, auto_load_libs=False)
    global data
    with open(variable_path) as f:
        data = json.load(f)
    # print(data)

    # We do not support Python eval (obviously)
    cfg = proj.analyses.CFG()
    # import ipdb; ipdb.set_trace()
    # nnode = len(list(cfg.kb.functions[0x416634].transition_graph.nodes))  # 279  mips
    # nedge = len(list(cfg.kb.functions[0x416634].transition_graph.edges))  # 517

    # nnode = len(list(cfg.kb.functions[0x41689c].transition_graph.nodes))  #  279 ppc
    # nedge = len(list(cfg.kb.functions[0x41689c].transition_graph.edges))  #  518

    # print(f"number of blocks: {nnode}, number of edges: {nedge}")
    # import ipdb; ipdb.set_trace()
    _hook_py_extensions(proj, cfg)
    proj.hook_symbol('__normalize_timespec', normalize_timespec())
    # run the state initializer
    init = cfg.kb.functions['RES0_init__']
    init_callable = proj.factory.callable(init.addr, perform_merge=False, add_options={ZERO_FILL_UNCONSTRAINED_MEMORY})
    init_callable.perform_call()
    initial_state = init_callable.result_state

    assert initial_state is not None

    # test switch on
    # switch_on(initial_state)

    init_time = time.time()
    print("------------init time: %s ----------" % (init_time - start_time))

    base_addr = int(data['variable_base_addr'], 16)
    time_addr = int(data['time_addr'], 16)
    software = data['software']


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
    # on start if start_button is on, it will skip START state
    sgr = proj.analyses.StateGraphRecovery(func, fields_output, software, time_addr, init_state=initial_state,
                                           inputs=inputs, fields_input=fields_input, switch_on=switch_on
                                           )

    sgr_time = time.time()
    print("------------sgr time: %s ----------" % (sgr_time - init_time))
    state_graph = sgr.state_graph
    # import ipdb; ipdb.set_trace()
    # import pickle
    # pickle.dumps(sgr, -1)

    # output the graph to a dot file
    from networkx.drawing.nx_agraph import write_dot
    match mode:
        case "x86":
            write_dot(sgr.state_graph, "graphs/package.dot")
        case "mips":
            write_dot(sgr.state_graph, "graphs/package_mips.dot")
        case "ppc":
            write_dot(sgr.state_graph, "graphs/package_ppc.dot")
    print("Number of nodes: %d" % state_graph.number_of_nodes())
    print("Number of edges: %d" % state_graph.number_of_edges())

    finder = RuleVerifier(state_graph)
    rule_start_time = time.time()

    rule = NoBothOnRule()
    r, src, dst = finder.verify(rule)
    # assert r is True

    rule1_time = time.time()
    print("------------rule1 time: %s ----------" % (rule1_time - rule_start_time))


    # import ipdb; ipdb.set_trace()
    rule = ValveMax15s(15)
    r, src, dst = finder.verify(rule)
    # assert r is False
    rule2_time = time.time()
    print("------------rule2 time: %s ----------" % (rule2_time - rule1_time))


if __name__ == "__main__":
    mode = sys.argv[1]
    test_packaging(mode)
