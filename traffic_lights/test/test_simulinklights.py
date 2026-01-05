import os
import struct
from typing import TYPE_CHECKING

import networkx
import sys
import json
import claripy
import angr
from angr.sim_options import ZERO_FILL_UNCONSTRAINED_MEMORY

sys.path.append("../")
import state_graph_recovery
from state_graph_recovery import MinDelayBaseRule, RuleVerifier, IllegalNodeBaseRule, MaxDelayBaseRule
if TYPE_CHECKING:
    import networkx

import time

# state graph acquired. define a rule
class MinDelayRule_PedGreen(MinDelayBaseRule):
    def node_a(self, graph: 'networkx.DiGraph'):
        # ped light is green
        for node in graph.nodes():
            if dict(node)['pg'] == 1 and dict(node)['pr'] == 0:
                yield node

    def node_b(self, graph: 'networkx.DiGraph', start: tuple):
        # ped light is red
        visited = [start]
        queue = [start]
        while queue:
            node = queue.pop(0)
            if dict(node)['pg'] == 0 and dict(node)['pr'] == 1:
                yield node
                continue
            for suc in graph.successors(node):
                if suc not in visited:
                    visited.append(suc)
                    queue.append(suc)


class MinDelayRule_Orange(MinDelayBaseRule):
    def node_a(self, graph: 'networkx.DiGraph'):
        # ped light is orange
        for node in graph.nodes():
            if dict(node)['yl'] == 1 and dict(node)['rl'] == 0:
                yield node

    def node_b(self, graph: 'networkx.DiGraph', start: tuple):
        # ped light is red
        visited = [start]
        queue = [start]
        while queue:
            node = queue.pop(0)
            if dict(node)['yl'] == 0 and dict(node)['rl'] == 1:
                yield node
                continue
            for suc in graph.successors(node):
                if suc not in visited:
                    visited.append(suc)
                    queue.append(suc)




class NoPedGreenCarGreen(IllegalNodeBaseRule):
    def verify_node(self, graph: 'networkx.DiGraph', node) -> bool:
        if dict(node)['gl'] == 1 and dict(node)['pg'] == 1:
            # both car green light and the pedestrian green light are on at the same time
            # this is bad!
            return False
        return True


class readDigitalPin(angr.SimProcedure):
    def run(self, pin):
        # import ipdb;
        # ipdb.set_trace()
        pin = self.state.regs._r0
        # get the int
        if pin.op == "BVV":
            pin = pin.concrete_value
        print("readDigitalPin")
        print(pin)
        val = self.state.globals[pin]

        return val

class writeDigitalPin(angr.SimProcedure):
    def run(self, pin, val):
        # import ipdb; ipdb.set_trace()
        pin = self.state.regs._r0
        val = self.state.regs._r1
        print("writeDigitalPin")
        print(pin, val)
        # get the int
        if pin.op == "BVV":
            pin = pin.concrete_value
        self.state.globals[pin] = val

        return None

def switch_on(state):
    # switch on
    state.globals[4] = 1

def test_blinky():
    binary_path = "../../artifacts/traffic_light_simulink/MyBlinky.elf"
    variable_path = ""
    start_time = time.time()
    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFG()
    nnode = len(list(cfg.kb.functions["MyBlinky_step"].blocks))
    print(f"number of blocks: {nnode}")
    proj.hook_symbol('writeDigitalPin', writeDigitalPin())
    proj.hook_symbol('readDigitalPin', readDigitalPin())


    # init = cfg.kb.functions['main']
    # init_callable = proj.factory.callable(init.addr, perform_merge=False)
    # init_callable.perform_call()
    # initial_state = init_callable.result_state
    # blank = proj.factory.blank_state(addr=init.addr, add_options={ZERO_FILL_UNCONSTRAINED_MEMORY})
    # blank.memory.store(0x40000140a, claripy.BVV(0xd2, 32), endness=proj.arch.memory_endness)
    # simgr = proj.factory.simgr(blank)
    # while simgr.active:
    #     print(simgr.active)
    #     if simgr.active[0].addr == 0x2279:
    #         for _ in range(10):
    #             simgr.step()
    #         simgr.active[0].memory.store(0x40001400, claripy.BVV(0, 32))
    #     if simgr.active[0].addr == 0x21b5:
    #         import ipdb; ipdb.set_trace()
    #
    #     simgr.step()

    init_time = time.time()
    print("------------init time: %s ----------" % (init_time - start_time))

    # define abstract fields
    fields_desc = {
        'state': (0x200009c1, "int", 1),
        'signal': (4, "pin", 1),
        'yl': (9, "pin", 1),
        'rl': (10, "pin", 1),
        'gl': (11, "pin", 1),
        'pr': (6, "pin", 1),
        'pg': (5, "pin", 1)}
        # 'active': (0x20000964, "int", 1)}

    fields = state_graph_recovery.AbstractStateFields(fields_desc)

    func = cfg.kb.functions['MyBlinky_step']
    initial_state = proj.factory.blank_state(addr=func.addr, add_options={ZERO_FILL_UNCONSTRAINED_MEMORY})
    initial_state.globals[4] = 0
    time_addr = 0x200009c2
    sgr = proj.analyses.StateGraphRecovery(func, fields, 'simulink', time_addr, init_state=initial_state, switch_on=switch_on,)
    sgr_time = time.time()
    print("------------sgr time: %s ----------" % (sgr_time - init_time))

    state_graph = sgr.state_graph

    # output the graph to a dot file
    from networkx.drawing.nx_agraph import write_dot
    write_dot(sgr.state_graph, "graphs/tl11.dot")
    print("number of nodes: ", state_graph.number_of_nodes())
    print("number of edges: ", state_graph.number_of_edges())


    finder = RuleVerifier(state_graph)
    rule = MinDelayRule_Orange(20.0)
    r, src, dst = finder.verify(rule)
    # assert r is True

    rule1_time = time.time()
    print("------------rule1 time: %s ----------" % (rule1_time - sgr_time))

    # import ipdb; ipdb.set_trace()
    rule = MinDelayRule_PedGreen(190.0)
    r, src, dst = finder.verify(rule)
    # assert r is False
    rule2_time = time.time()
    print("------------rule2 time: %s ----------" % (rule2_time - rule1_time))

    rule = NoPedGreenCarGreen()
    r, src, dst = finder.verify(rule)
    # assert r is True
    rule3_time = time.time()
    print("------------rule3 time: %s ----------" % (rule3_time - rule2_time))


if __name__ == "__main__":
    test_blinky()
