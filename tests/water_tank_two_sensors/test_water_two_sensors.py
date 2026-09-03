import os
import struct
import time
from typing import TYPE_CHECKING, Generator, Any, Iterable, Tuple, List

import networkx
import sys
import json
import claripy
import angr
import pytest

from . import state_graph_recovery
from taveren import (
    AbstractStateFields,
    MinDelayBaseRule,
    RuleVerifier,
    IllegalNodeBaseRule,
    MaxDelayBaseRule,
    IllegalTransitionBaseRule,
    BaseRule,
)

if TYPE_CHECKING:
    import networkx

# Get path relative to this test file (important for pytest)
TEST_DIR = os.path.dirname(os.path.realpath(__file__))
GRAPHS_DIR = os.path.join(TEST_DIR, '../../graphs')

# Ensure graphs directory exists
os.makedirs(GRAPHS_DIR, exist_ok=True)

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

@pytest.mark.parametrize("mode", ["WT1", "WT3"])
def test_water_tank(mode: str):
    if mode == 'WT1':
        binary_path = os.path.join(TEST_DIR, '../../artifacts/water_tank/build/water_tank.so')
        variable_path = os.path.join(TEST_DIR, 'water_tank.json')
        graph_output = os.path.join(GRAPHS_DIR, 'water_tank_fbd_two_sensors-1.dot')
    elif mode == 'WT3':
        binary_path = os.path.join(TEST_DIR,
                                   '../../artifacts/water_tank_sfc_two_sesnors/build/water_tank_sfc_two_sesnors.so')
        variable_path = os.path.join(TEST_DIR, 'water_tank_sfc_twosensors.json')
        graph_output = os.path.join(GRAPHS_DIR, 'water_tank_sfc_two_sesnors-3.dot')
    else:
        pytest.fail(f"Unknown mode: {mode}")

    start_time = time.time()

    proj = angr.Project(binary_path, auto_load_libs=False)
    with open(variable_path) as f:
        data = json.load(f)

    cfg = proj.analyses.CFG()

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

    outputs, inputs = generate_field_desc(data)
    fields_output = AbstractStateFields(outputs)
    fields_input = AbstractStateFields(inputs)
    func = cfg.kb.functions['RES0_run__']
    sgr = proj.analyses.StateGraphRecoveryTwoSensor(func, fields_output, software, time_addr, init_state=initial_state,
                                        inputs = inputs, fields_input=fields_input
                                           )
    sgr_time = time.time()
    print("------------sgr time: %s ----------" % (sgr_time - init_time))
    state_graph = sgr.state_graph

    # output the graph to a dot file
    from networkx.drawing.nx_agraph import write_dot
    write_dot(sgr.state_graph, graph_output)
    print(f"Graph written to: {graph_output}")
    print("Number of nodes: %d" % state_graph.number_of_nodes())
    print("Number of edges: %d" % state_graph.number_of_edges())

    finder = RuleVerifier(state_graph)
    rule_start_time = time.time()

    rule = SensorExclusionRule()
    r, src, dst = finder.verify(rule)

    rule1_time = time.time()
    print("------------rule1 time: %s ----------" % (rule1_time - rule_start_time))

    rule2 = WaterHighPumpOff()
    r, src, dst = finder.verify(rule2)
    rule2_time = time.time()
    print("------------rule2 time: %s ----------" % (rule2_time - rule1_time))
