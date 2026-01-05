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
from state_graph_recovery import MinDelayBaseRule, RuleVerifier, IllegalNodeBaseRule, MaxDelayBaseRule, BaseRule
# from angr.analyses.analysis import Analysis, AnalysesHub
# AnalysesHub.register_default('StateGraphRecovery', StateGraphRecoveryAnalysis)
# from state_graph_recovery.apis import generate_patch, apply_patch, apply_patch_on_state, EditDataPatch

if TYPE_CHECKING:
    import networkx

import time

binaries_base = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries')


# when insert more amount of money, give change
class GiveChange(BaseRule):
    # calculate the money inserted, if sum is over 75 cents, but give change is not executed, return false
    def moneysum(self, graph: 'networkx.DiGraph', path) -> Generator[float, None, None]:

        sum = 0
        for src, dst in zip(path, path[1:]):
            max = 0
            for data in graph.get_edge_data(src, dst).values():
                # calculate the max value of each edge
                value = 0
                if data["dollar_delta"] is None and data["quarter_delta"] is None:
                    continue
                elif data["dollar_delta"] is None and data["quarter_delta"] is not None:
                    value +=1
                    value += 0.25 if data["quarter_delta"] > 0 else 0
                elif data["dollar_delta"] is not None and data["quarter_delta"] is None:
                    value += 1 if data["dollar_delta"] > 0 else 0
                    value += 0.25
                else:
                    value += 1 if data["dollar_delta"] > 0 else 0
                    value += 0.25 if data["quarter_delta"] > 0 else 0
                if value > max:
                    max = value
                sum += max
            print(sum)
            if sum > 0.75:
                yield sum, src, dst

    def eval(self, graph) -> Tuple[bool, Any, Any]:
        # find state node and drop can node
        node_wait = [node for node in graph.nodes() if dict(node)["NODE_CTR"] == 1][0]
        node_drop = [node for node in graph.nodes() if dict(node)["vmstate"] == 4][0]
        node_change = [node for node in graph.nodes() if dict(node)["vmstate"] == 3][0]
        print(list(networkx.all_simple_paths(graph, node_wait, node_drop)))
        for path in networkx.all_simple_paths(graph, node_wait, node_drop):


            for sum, src, dst in self.moneysum(graph, path):
                if sum > 0.75 and node_change not in path:
                    print(path)
                    return False, src, dst

        return True, None, None


class dollarInserted(angr.SimProcedure):
    def run(self):
        # if self.state.solver.eval(self.state.globals[10]) == 1:
        #     return True
        # else:
        #     return False
        return claripy.If(self.state.globals[10] != 0, claripy.BVV(1, 32), claripy.BVV(0, 32))

class quatertInserted(angr.SimProcedure):
    def run(self):
        # if self.state.solver.eval(self.state.globals[11]) == 1:
        #     return True
        # else:
        #     return False
        return claripy.If(self.state.globals[11] != 0, claripy.BVV(1, 32), claripy.BVV(0, 32))

class dropCan(angr.SimProcedure):
    def run(self):
        print("Drop Can")
        return None

class giveChange(angr.SimProcedure):
    def run(self):
        print("Give Change")
        return None


# state graph acquired. define a rule

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

def test_vending_machine():
    binary_path = '../../artifacts/vending_machine/arduino_build_389120/vending_machine.ino.elf'
    variable_path = 'vending_machine.json'


    start_time = time.time()

    proj = angr.Project(binary_path, auto_load_libs=False)
    global data
    with open(variable_path) as f:
        data = json.load(f)
    # print(data)

    # We do not support Python eval (obviously)
    cfg = proj.analyses.CFG()

    # nnode = len(list(cfg.kb.functions["_Z14vendingMachinev"].transition_graph.nodes))
    # print(f"number of nodes: {nnode}")
    # nedge = len(list(cfg.kb.functions["_Z14vendingMachinev"].transition_graph.edges))
    # print(f"number of edges: {nedge}")
    # import ipdb; ipdb.set_trace()
    proj.hook_symbol('_Z14dollarInsertedv', dollarInserted())
    proj.hook_symbol('_Z15quarterInsertedv', quatertInserted())
    proj.hook_symbol('_Z7dropCanv', dropCan())
    proj.hook_symbol('_Z10giveChangev', giveChange())

    # run the state initializer
    # init = cfg.kb.functions['config_init__']
    # init_callable = proj.factory.callable(init.addr, perform_merge=False)
    # init_callable.perform_call()
    # initial_state = init_callable.result_state


    # assert initial_state is not None
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
    func = cfg.kb.functions['loop']
    initial_state = proj.factory.blank_state(addr = func.addr)
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
    write_dot(sgr.state_graph, "./graphs/vending_machine.dot")


    print("Number of nodes: %d" % state_graph.number_of_nodes())
    print("Number of edges: %d" % state_graph.number_of_edges())

    finder = RuleVerifier(state_graph)
    rule_start_time = time.time()

    rule1 = GiveChange()
    r, src, dst = finder.verify(rule1)
    # assert r is True

    rule1_time = time.time()
    print("------------rule1 time: %s ----------" % (rule1_time - rule_start_time))


if __name__ == "__main__":
    test_vending_machine()
