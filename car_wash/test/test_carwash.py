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

if TYPE_CHECKING:
    import networkx

import time
import pickle


# state graph acquired. define a rule
# water and soap sprinkler should not be on at the same time
class NoTwoSprinklerOn(IllegalNodeBaseRule):
    def verify_node(self, graph: 'networkx.DiGraph', node: 'networkx.Node') -> bool:
        if dict(node)['SOAP_SPRINKLER'] == 1 and dict(node)['WATER_SPRINKLER'] == 1:
            return False
        return True

# Conveyor belt should not be on for more than 10 seconds continuously
class MaxDelayMotor(MaxDelayBaseRule):
    def node_a(self, graph: 'networkx.DiGraph'):
        for node in graph.nodes():
            if dict(node)['CONVEYOR_MOTOR'] == 1:
                yield node

    def node_b(self, graph: 'networkx.DiGraph', start: tuple) :
        visited = [start]
        queue = [start]
        while queue:
            node = queue.pop(0)
            if dict(node)['CONVEYOR_MOTOR'] == 0:
                yield node
                continue   # stop searching path after this node
            for suc in graph.successors(node):
                if suc not in visited:
                    visited.append(suc)
                    queue.append(suc)
                    # print(queue)

# after the car wash starts (after selection), even if the selection button is pressed again, the service should not change


class normalize_timespec(angr.SimProcedure):
    def run(self):
        # print("in normalize_timespec")
        # import ipdb; ipdb.set_trace()
        return None

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


def test_carwash(mode:str):
    base_dir = os.path.dirname(os.path.abspath(__file__))

    if mode == "x86":
        binary_path = os.path.join(base_dir, "../../artifacts/car_wash/build/car_wash.so") #x86_64
        variable_path = os.path.join(base_dir, "carwash.json")
    elif mode == "arm":
        binary_path = os.path.join(base_dir, "../../artifacts/car_wash/build/carwash-mkr1010.elf")   # arm
        variable_path = os.path.join(base_dir, "carwash_arm.json")
    else:
        print("unknown mode")
        return

    start_time = time.time()

    proj = angr.Project(binary_path, auto_load_libs=False)
    global data
    with open(variable_path) as f:
        data = json.load(f)
    # print(data)

    # We do not support Python eval (obviously)
    cfg = proj.analyses.CFG()
    # import ipdb; ipdb.set_trace()
    # nnode = len(list(cfg.kb.functions[0x438395].transition_graph.nodes))     # 2137  x86_64
    # nedge = len(list(cfg.kb.functions[0x438395].transition_graph.edges))      # 4025

    # nnode = len(list(cfg.kb.functions[0x2da5].transition_graph.nodes))     # 2152  arm
    # nedge = len(list(cfg.kb.functions[0x2da5].transition_graph.edges))      # 4037
    #
    # print(f"number of blocks: {nnode}, number of edges: {nedge}")
    # import ipdb; ipdb.set_trace()
    # _hook_py_extensions(proj, cfg)
    proj.hook_symbol('__normalize_timespec', normalize_timespec())

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
    if mode == "arm":
        write_dot(sgr.state_graph, "./graphs/car_wash_arm.dot")
    elif mode == "x86":
        write_dot(sgr.state_graph, "./graphs/car_wash_x86.dot")
    print(f"[.] Total iteration number: {sgr.iter_count}")

    import pickle
    pkl_file = "./car_wash_arm.pkl" if mode == "arm" else "./car_wash_x86.pkl"
    # with open("./car_wash_graph_arm_o.pkl", "wb") as f:
    # with open("./car_wash_x86_o.pkl", "wb") as f:
    with open(pkl_file, "wb") as f:
        pickle.dump(sgr.state_graph, f)



def test_policy():
    with open("./car_wash_x86.pkl", "rb") as f:
    # with open("./car_wash_arm.pkl", "rb") as f:
        state_graph_multi = pickle.load(f)
    # import ipdb; ipdb.set_trace()
    state_graph = networkx.DiGraph(state_graph_multi)

    finder = RuleVerifier(state_graph)
    rule_start_time = time.time()

    rule = NoTwoSprinklerOn()
    r, src, dst = finder.verify(rule)
    rule1_time = time.time()
    print("------------rule1 time: %s ----------" % (rule1_time - rule_start_time))


    rule = MaxDelayMotor(10.0)
    # import ipdb; ipdb.set_trace()
    r, src, dst = finder.verify(rule)
    rule2_time = time.time()
    print("------------rule2 time: %s ----------" % (rule2_time - rule1_time))


if __name__ == "__main__":
    mode = sys.argv[1]
    # run python test_carwash.py arm
    # run python test_carwash.py x86
    test_carwash(mode)    # comment out this line for testing policy only
    test_policy()