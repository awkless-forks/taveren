import os
from typing import Any, Tuple

import networkx
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
)

import time
from taveren.env_model import generate_field_desc

TEST_DIR = os.path.dirname(os.path.realpath(__file__))


# state graph acquired. define a rule
# if anomaly is false (normal), the rocket should not dump fuel, release booster and tank
class NoDumpFuelRuleNormal(IllegalTransitionBaseRule):
    def verify_node(self, graph: "networkx.DiGraph", node: Any) -> Tuple[bool, Any]:
        for dst in graph.successors(node):
            if dict(dst)["dumpFuel"] == 1:
                for edge_data in graph.get_edge_data(node, dst).values():
                    if edge_data["anomaly_delta"] == 0.0:
                        return False, dst
        return True, None


# if abort in earlier stage, the rocket cannot release tank without releasing booster
class ReleaseBoosterLastRule(IllegalNodeBaseRule):
    def verify_node(self, graph: "networkx.DiGraph", node: "networkx.Node") -> bool:
        if (
            dict(node)["dumpFuel"] == 1
            and dict(node)["releaseBoosters"] == 0
            and dict(node)["releaseTank"] == 1
        ):
            return False
        return True


def call_one_func(state: "SimState") -> "SimState":
    ret_trap = 0x1F32FF40

    if state.project.arch.call_pushes_ret:
        state.stack_push(claripy.BVV(ret_trap, state.project.arch.bits))

    simgr = state.project.factory.simgr(state)
    while simgr.active:
        print(simgr.active)
        s = simgr.active[0]
        # if len(simgr.active) > 1:
        # if s.addr == 0x458158:  # armed()
        #     # TODO: Should i move since i initialized motors?
        #     # rdi is motors object i dont know how to initialize it
        #     s.memory.store(s.regs.rdi + 0x80, claripy.BVV(1, 8), endness = s.project.arch.memory_endness)

        # if s.addr == 0x47dfc4:
        #     print("after abs")

        simgr.stash(
            lambda x: x.addr == ret_trap, from_stash="active", to_stash="finished"
        )
        simgr.step()

    initial_states = simgr.finished
    return initial_states[0]


@pytest.mark.parametrize("mode", ["modelogic", "abortlogic", "full"])
def test_abort(mode: str):
    binary_path = os.path.join(TEST_DIR, "../fixtures/binaries/sf_launchabort.exe")
    variable_path = os.path.join(TEST_DIR, "abort.json")

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

    # run the state initializer
    initialize_addr = 0x401F7A
    init = cfg.kb.functions[initialize_addr]
    blank = proj.factory.blank_state(
        addr=initialize_addr,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SIMPLIFY_CONSTRAINTS,
        },
    )
    initial_state = call_one_func(blank)

    assert initial_state is not None
    init_time = time.time()

    # initial_state.regs.rip = 0x401EBC
    # simgr = proj.factory.simgr(initial_state)
    # simgr.step()
    # initial_state = simgr.active[0]
    print("------------init time: %s ----------" % (init_time - start_time))

    if mode == "abortlogic":
        # set anomaly to true
        initial_state.memory.store(
            0x408B48,
            claripy.FPV(1.0, claripy.fp.FSORT_DOUBLE),
            endness=proj.arch.memory_endness,
        )  # comment out this for ModeLogic and full

    base_addr = int(data["variable_base_addr"], 16)
    time_addr = int(data["time_addr"], 16)
    software = data["software"]

    # define abstract fields
    outputs, inputs = generate_field_desc(data)
    # pre-constrain configuration variables so that we can track them
    fields_output = AbstractStateFields(outputs)
    fields_input = AbstractStateFields(inputs)
    LaunchAbortController_addr = 0x401EBC
    # func = cfg.kb.functions[LaunchAbortController_addr]
    sgr = proj.analyses.StateGraphRecoveryAbort(
        LaunchAbortController_addr,
        fields_output,
        software,
        time_addr,
        init_state=initial_state,
        inputs=inputs,
        fields_input=fields_input,
        mode=mode,
    )
    sgr_time = time.time()
    print("------------sgr time: %s ----------" % (sgr_time - init_time))
    state_graph = sgr.state_graph
    # import pickle
    # pickle.dumps(sgr, -1)

    # output the graph to a dot file
    from networkx.drawing.nx_agraph import write_dot

    graphs_dir = os.path.join(TEST_DIR, "graphs")
    os.makedirs(graphs_dir, exist_ok=True)
    if mode == "modelogic":
        write_dot(sgr.state_graph, os.path.join(graphs_dir, "abort1.dot"))
    elif mode == "abortlogic":
        write_dot(sgr.state_graph, os.path.join(graphs_dir, "abort2.dot"))
    elif mode == "full":
        write_dot(sgr.state_graph, os.path.join(graphs_dir, "abort3.dot"))
    print("node number: ", state_graph.number_of_nodes())
    print("edge number: ", state_graph.number_of_edges())

    if mode == "full":
        # verify rules on full state machine
        finder = RuleVerifier(state_graph)
        rule_start_time = time.time()

        rule1 = NoDumpFuelRuleNormal()
        r, src, dst = finder.verify(rule1)
        # assert r is True

        rule1_time = time.time()
        print("------------rule1 time: %s ----------" % (rule1_time - rule_start_time))

        rule2 = ReleaseBoosterLastRule()
        r, src, dst = finder.verify(rule2)
        # assert r is False
        rule2_time = time.time()
        print("------------rule2 time: %s ----------" % (rule2_time - rule1_time))
