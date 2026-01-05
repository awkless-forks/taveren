import os
import struct
from mimetypes import inited
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

def generate_field_desc(var_info):
    # define abstract fields
    fields_output = {}
    fields_input = {}
    var_base_addr = var_info["variable_base_addr"]
    for variable in var_info['variables']:
        addr = var_base_addr + variable['address'] if isinstance(var_base_addr, int) else int(var_base_addr, 16) + int(
            variable['address'], 16)
        if "output" in variable["mode"] or "statevar" in variable["mode"]:
            fields_output[variable['name']] = (addr,
                                             variable['type'],
                                             variable['size'],
                                             )
        if "input" in variable["mode"]:
            fields_input[variable['name']] = (addr,
                                               variable['type'],
                                               variable['size'],
                                               )

    return fields_output, fields_input


def test_ihex_parser():
    binary_path = "../../artifacts/binaries/ihex_parser"
    variable_path = "ihex_parser.json"

    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()

    with open(variable_path) as f:
        data = json.load(f)

    outputs, inputs = generate_field_desc(data)
    fields_desc = outputs

    blank = proj.factory.blank_state(addr = 0x401479,
        add_options={angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.SIMPLIFY_CONSTRAINTS}
    )
    blank.regs.rsp = 0x7ffffffffff0000
    blank.regs.rdi = 0x7ffffffffff2000
    blank.regs.rsi = 0x2c  # random length

    step_state = blank.step().successors[0]
    init_state = step_state.step().successors[0]

    fields = state_graph_recovery.AbstractStateFields(fields_desc)

    loop_start = 0x4014a8
    sgr = proj.analyses.StateGraphRecovery(
        loop_start,
        fields,
        "",
        0,
        init_state=init_state,
        inputs=inputs,
    )

    # output the graph to a dot file
    from networkx.drawing.nx_agraph import write_dot
    write_dot(sgr.state_graph, "graphs/ihex.dot")
    print("nodes:", sgr.state_graph.number_of_nodes())
    print("edges:", sgr.state_graph.number_of_edges())
    # import ipdb; ipdb.set_trace()


if __name__ == "__main__":
    test_ihex_parser()
