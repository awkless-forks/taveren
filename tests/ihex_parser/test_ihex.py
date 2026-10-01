import os

import json
import angr

from . import state_graph_recovery
from taveren import AbstractStateFields
from taveren.env_model import generate_field_desc

TEST_DIR = os.path.dirname(os.path.realpath(__file__))


def test_ihex_parser():
    binary_path = os.path.join(TEST_DIR, "../fixtures/binaries/ihex_parser")
    variable_path = os.path.join(TEST_DIR, "ihex_parser.json")

    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()

    with open(variable_path) as f:
        data = json.load(f)

    outputs, inputs = generate_field_desc(data)
    fields_desc = outputs

    blank = proj.factory.blank_state(
        addr=0x401479,
        add_options={
            angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SIMPLIFY_CONSTRAINTS,
        },
    )
    blank.regs.rsp = 0x7FFFFFFFFFF0000
    blank.regs.rdi = 0x7FFFFFFFFFF2000
    blank.regs.rsi = 0x2C  # random length

    step_state = blank.step().successors[0]
    init_state = step_state.step().successors[0]

    fields = AbstractStateFields(fields_desc)

    loop_start = 0x4014A8
    sgr = proj.analyses.StateGraphRecoveryIhex(
        loop_start,
        fields,
        "",
        0,
        init_state=init_state,
        inputs=inputs,
    )

    # output the graph to a dot file
    from networkx.drawing.nx_agraph import write_dot

    graphs_dir = os.path.join(TEST_DIR, "graphs")
    os.makedirs(graphs_dir, exist_ok=True)
    write_dot(sgr.state_graph, os.path.join(graphs_dir, "ihex.dot"))
    print("nodes:", sgr.state_graph.number_of_nodes())
    print("edges:", sgr.state_graph.number_of_edges())


if __name__ == "__main__":
    test_ihex_parser()
