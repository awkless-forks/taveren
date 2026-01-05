import os
import struct
from typing import TYPE_CHECKING, Any, Dict, List, Tuple

import networkx
import sys
import json
import claripy
import angr
sys.path.append("../")
import state_graph_recovery
from state_graph_recovery import MinDelayBaseRule, RuleVerifier, IllegalNodeBaseRule, MaxDelayBaseRule, IllegalTransitionBaseRule
# from angr.analyses.analysis import Analysis, AnalysesHub
# AnalysesHub.register_default('StateGraphRecovery', StateGraphRecoveryAnalysis)
# from state_graph_recovery.apis import generate_patch, apply_patch, apply_patch_on_state, EditDataPatch

if TYPE_CHECKING:
    import networkx

import time
from arduino_peripherial import *

# state graph acquired. define a rule
class NoUpOnTopFloorRule(IllegalTransitionBaseRule):
    def verify_node(self, graph: 'networkx.DiGraph', node: Any) -> Tuple[bool, Any]:
        for succ in graph.successors(node):
            if dict(node)['level'] == 4 and dict(succ)['dir'] == 1:
                return False, succ
        return True, None

class NoDownOnGroundFloorRule(IllegalTransitionBaseRule):
    def verify_node(self, graph: 'networkx.DiGraph', node: Any) -> Tuple[bool, Any]:
        for succ in graph.successors(node):
            if dict(node)['level'] == 1 and dict(succ)['dir'] == -1:
                return False, succ
        return True, None

class PressHighGoUpRule(IllegalTransitionBaseRule):
    def verify_node(self, graph: 'networkx.DiGraph', node: Any) -> Tuple[bool, Any]:
        if dict(node)['level'] < 4:
            for succ in graph.successors(node):
                # if the elevator is lower than the 4th floor, and the floor 4 button is pressed, go up
                for edge_data in graph.get_edge_data(node, succ).values():
                    if edge_data['btn4_delta'] == 1 and (dict(succ)['dir'] < 1 or dict(succ)['level'] <= dict(node)['level']):
                        return False, succ
        return True, None

class up(angr.SimProcedure):
    def run(self):
        print("in up")
        self.state.globals[0x40] = 1

class down(angr.SimProcedure):
    def run(self):
        print("in down")
        self.state.globals[0x40] = -1



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
        if "output" in variable["type"]:
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

def test_elevator():

    variant = sys.argv[1]  # "ARM" or "AVR"
    print("Testing elevator variant:", variant)

    base_dir = os.path.dirname(os.path.realpath(__file__))

    binary_path = os.path.join(base_dir, "../../artifacts/elevator/elevator.ino.elf")
    variable_path = os.path.join(base_dir, "elevator.json")

    if variant == "AVR":
        binary_path = os.path.join(base_dir, "../../artifacts/elevator/elevator_uno_O0.ino.elf")
        variable_path = os.path.join(base_dir, "elevator_uno_O0.json")

        # import AVR platform support
        import angr_platforms

        from angr_platforms.avr.arch_avr import ArchAVR
        from angr_platforms.avr.lift_avr import LifterAVR

        main_opts = {"arch": ArchAVR()}

    else:
        main_opts = {}


    start_time = time.time()

    proj = angr.Project(binary_path, auto_load_libs=False, main_opts=main_opts)
    global data
    with open(variable_path) as f:
        data = json.load(f)
    # print(data)

    # import ipdb; ipdb.set_trace()
    proj.hook_symbol("delay", delay())
    proj.hook_symbol("pinMode", pinMode())
    proj.hook_symbol("digitalWrite", digitalWrite())
    proj.hook_symbol("digitalRead", digitalRead())
    proj.hook_symbol("_Z2upv", up())
    proj.hook_symbol("_Z4downv", down())

    match variant:
        case "ARM":
            proj.hook_symbol("_ZN7arduino5Print5printEPKc", print_all())
            proj.hook_symbol("_ZN7arduino5Print5printEii", print_all())
            proj.hook_symbol("_ZN7arduino5Print7printlnEPKc", print_all())

        case "AVR":
            proj.hook_symbol("_ZN5Print5printEPKc", print_all())
            proj.hook_symbol("_ZN5Print5printEii", print_all())
            proj.hook_symbol("_ZN5Print7printlnEPKc", print_all())

        case _:
            raise Exception("Unsupported variant")


    # nnode = len(list(cfg.kb.functions[0x42c034].blocks))
    # print(f"number of blocks: {nnode}")
    # import ipdb; ipdb.set_trace()

    # run the state initializer
    init = proj.loader.find_symbol("setup")
    init_callable = proj.factory.callable(init.rebased_addr, perform_merge=False)
    init_callable.perform_call()
    initial_state = init_callable.result_state
    # initial_state = proj.factory.blank_state(addr=0x21B1)
    assert initial_state is not None
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
    cfg = proj.analyses.CFG(show_progressbar=True, force_smart_scan=False)
    func = cfg.kb.functions['loop']
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

    dot_file = "./graphs/elevator.dot" if variant == "ARM" else "./graphs/elevator_avr.dot"
    dot_file = os.path.join(base_dir, dot_file)

    write_dot(sgr.state_graph, dot_file)
    print("Number of nodes: %d" % state_graph.number_of_nodes())
    print("Number of edges: %d" % state_graph.number_of_edges())


    finder = RuleVerifier(state_graph)
    rule_start_time = time.time()

    rule1 = NoUpOnTopFloorRule()
    r, src, dst = finder.verify(rule1)
    # assert r is True

    rule1_time = time.time()
    print("------------rule1 time: %s ----------" % (rule1_time - rule_start_time))


    # import ipdb; ipdb.set_trace()
    rule2 = NoDownOnGroundFloorRule()
    r, src, dst = finder.verify(rule2)
    # assert r is False
    rule2_time = time.time()
    print("------------rule2 time: %s ----------" % (rule2_time - rule1_time))

    rul3start = time.time()
    rule3 = PressHighGoUpRule()
    r, src, dst = finder.verify(rule3)
    # assert r is True
    rule3_time = time.time()
    print("------------rule3 time: %s ----------" % (rule3_time - rul3start))



if __name__ == "__main__":
    test_elevator()
