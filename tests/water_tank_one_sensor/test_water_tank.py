import os
import struct
from typing import TYPE_CHECKING, Any, Tuple

import networkx
import sys
import json
import claripy
import angr
import time
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

class SensorExclusionRule(BaseRule):
    def eval(self, graph: 'networkx.DiGraph') -> Tuple[bool, Any, Any]:
        for (src, dst) in graph.edges():
            for edge_data in graph.get_edge_data(src, dst).values():
                water_level = edge_data["water_level_delta"] if edge_data["water_level_delta"] is not None else 50
                if water_level < 15 and water_level > 85:
                    return False, src, dst
        return True, None, None


class WaterHighPumpOff(IllegalTransitionBaseRule):
    def verify_node(self, graph: 'networkx.DiGraph', node: Any) -> Tuple[bool, Any]:
        for dst in graph.successors(node):
            if dict(dst)["MOTOR"] == 1:
                for edge_data in graph.get_edge_data(node, dst).values():
                    if edge_data["water_level_delta"] is None or edge_data["water_level_delta"] > 85:
                        return False, dst
        return True, None


def _hook_py_extensions(proj, cfg):
    proj.hook(cfg.kb.functions['PYTHON_EVAL_body__'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['PYTHON_POLL_body__'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['__publish_debug'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['__publish_py_ext'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())


def generate_field_desc(var_info):
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


def test_water_tank():
    # Paths relative to this test file
    binary_path = os.path.join(TEST_DIR, '../../artifacts/water_tank_sfc_one_sensor/build/water_tank_sfc_one_sensor.so')
    variable_path = os.path.join(TEST_DIR, 'water_tank.json')

    start_time = time.time()

    proj = angr.Project(binary_path, auto_load_libs=False)
    with open(variable_path) as f:
        data = json.load(f)

    cfg = proj.analyses.CFG()
    _hook_py_extensions(proj, cfg)

    init = cfg.kb.functions['config_init__']
    init_callable = proj.factory.callable(init.addr, perform_merge=False)
    init_callable.perform_call()
    initial_state = init_callable.result_state

    assert initial_state is not None
    init_time = time.time()
    print(f"init time: {init_time - start_time:.2f}s")

    base_addr = int(data['variable_base_addr'], 16)
    time_addr = int(data['time_addr'], 16)
    software = data['software']

    outputs, inputs = generate_field_desc(data)

    fields_output = AbstractStateFields(outputs)
    fields_input = AbstractStateFields(inputs)
    func = cfg.kb.functions['__run']
    sgr = proj.analyses.StateGraphRecovery(
        func, fields_output, software, time_addr,
        init_state=initial_state,
        inputs=inputs,
        fields_input=fields_input
    )
    sgr_time = time.time()
    print(f"sgr time: {sgr_time - init_time:.2f}s")

    state_graph = sgr.state_graph

    # Ensure output directory exists
    graphs_dir = os.path.join(TEST_DIR, 'graphs')
    os.makedirs(graphs_dir, exist_ok=True)

    from networkx.drawing.nx_agraph import write_dot
    write_dot(sgr.state_graph, os.path.join(graphs_dir, "water_tank.dot"))

    print(f"Number of nodes: {state_graph.number_of_nodes()}")
    print(f"Number of edges: {state_graph.number_of_edges()}")

    finder = RuleVerifier(state_graph)
    rule_start_time = time.time()

    rule = SensorExclusionRule()
    r, src, dst = finder.verify(rule)

    rule1_time = time.time()
    print(f"rule1 time: {rule1_time - rule_start_time:.2f}s")

    rule2 = WaterHighPumpOff()
    r, src, dst = finder.verify(rule2)

    rule2_time = time.time()
    print(f"rule2 time: {rule2_time - rule1_time:.2f}s")
