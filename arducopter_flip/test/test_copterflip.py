import os
import struct
from typing import TYPE_CHECKING

import networkx
import sys
import json
import claripy
import angr
from angr.sim_options import ZERO_FILL_UNCONSTRAINED_MEMORY
from angr.analyses.analysis import Analysis, AnalysesHub
sys.path.append("../")
import state_graph_recovery
from state_graph_recovery import StateGraphRecoveryAnalysis
AnalysesHub.register_default('StateGraphRecovery', StateGraphRecoveryAnalysis)
from state_graph_recovery import MinDelayBaseRule, RuleVerifier, IllegalNodeBaseRule, IllegalTransitionBaseRule, MaxDelayBaseRule
from state_graph_recovery.apis import generate_patch, apply_patch, apply_patch_on_state, EditDataPatch

if TYPE_CHECKING:
    import networkx

import time
import pickle



class Abandon0Throttle(IllegalNodeBaseRule):
    def verify_node(self, graph: 'networkx.DiGraph', node) -> bool:
        if dict(node)['state'] == 5 and dict(node)['throttle'] > 0.0:
            # throttle is on when in abandon state
            # this is bad!
            return False
        return True


class TimeoutAbandon(MaxDelayBaseRule):
    def node_a(self, graph:'networkx.DiGraph'):
        # start state
        for node in graph.nodes():
            if dict(node)['state'] == 0:
                yield node

    def node_b(self, graph:'networkx.DiGraph', start: tuple):
        # abandon state
        visited = [start]
        queue = [start]
        while queue:
            # import ipdb; ipdb.set_trace()
            node = queue.pop(0)
            if dict(node)['state'] == 5:
                yield node
            else:
                for suc in graph.successors(node):
                    if suc not in visited:
                        visited.append(suc)
                        queue.append(suc)



class NoFlipBelow10m(IllegalTransitionBaseRule):
    def verify_node(self, graph, src):
        for dst in graph.successors(src):
            edge_data = graph.get_edge_data(src, dst)
            if any('attitude' in key for key in edge_data.keys()):
                return True, None
            else:
                return False, dst


class millis(angr.SimProcedure):
    def run(self):
        # import ipdb; ipdb.set_trace()
        # time_addr = 0x200001d8 # a random number
        prev = self.state.memory.load(time_addr, 4, endness=self.arch.memory_endness)
        # self.state.memory.store(time_addr, prev + usec, endness=self.arch.memory_endness)
        # print(self.state.solver.eval(self.state.memory.load(0x200002fc, 4, endness=self.arch.memory_endness)))
        self.state.regs._eax = prev
        return None


class WriteEvent(angr.SimProcedure):
    def run(self, this, logevent):
        print("[LOG EVENT] ", logevent)
        return None

#
# class sinf(angr.SimProcedure):
#     def run(self, x):
#         print("in sinf")
#         import ipdb; ipdb.set_trace()
#         return None
#
#
# class cosf(angr.SimProcedure):
#     def run(self, x):
#         print("in cosf")
#         import ipdb; ipdb.set_trace()
#         return None


class is_zero(angr.SimProcedure):
    def run(self, x):
        # print("in is_zero!")
        # import ipdb;ipdb.set_trace()
        x_num = self.state.regs._xmm0
        x_bytes = struct.pack("@P", x_num.args[0])
        # x_float = struct.unpack("<d", x_bytes)[0]
        x_float = struct.unpack("<f", x_bytes[:4])[0]
        self.state.regs._al = claripy.If(x_float==0, claripy.BVV(1, 8), claripy.BVV(0, 8))
        return None


class abs(angr.SimProcedure):
    def run(self, x):
        # print("in abs!")
        # import ipdb;ipdb.set_trace()
        x_num = self.state.regs._eax
        self.state.regs._eax = claripy.If(claripy.SGE(x_num, 0), x_num, -x_num)
        return None


def call_one_func(state: 'SimState') -> 'SimState':
    ret_trap = 0x1f32ff40

    if state.project.arch.call_pushes_ret:
        state.stack_push(claripy.BVV(ret_trap, state.project.arch.bits))

    simgr = state.project.factory.simgr(state)
    while simgr.active:
        # print(simgr.active)
        s = simgr.active[0]
        # if len(simgr.active) > 1:
        #     import ipdb; ipdb.set_trace()
        if s.addr == 0x458158:  # armed()
            # rdi is motors object i dont know how to initialize it
            # import ipdb; ipdb.set_trace()
            s.memory.store(s.regs.rdi + 0x80, claripy.BVV(1, 8), endness = s.project.arch.memory_endness)

        # if s.addr == 0x47dfc4:
        #     print("after abs")
        #     import ipdb; ipdb.set_trace()

        simgr.stash(lambda x: x.addr == ret_trap, from_stash='active', to_stash='finished')
        simgr.step()

    initial_states = simgr.finished
    return initial_states


# analyse state machine in ModeFlip
def test_flip(binary_path, variable_path=None):

    start_time = time.time()

    proj = angr.Project(binary_path)
    # cfg = None
    # if os.path.exists(cfg_path):
    #     with open(cfg_path, "rb") as f:
    #         cfg = pickle.load(f)
    # else:
    #     cfg = proj.analyses.CFG(binary=proj.loader.main_object, show_progressbar=True)
    #     # import ipdb; ipdb.set_trace()
    #     # with open(cfg_path, "wb") as f:
    #     #     pickle.dump(cfg, f)
    #
    # nnode = len(list(cfg.kb.functions['_ZN8ModeFlip3runEv'].blocks))
    # print(f"number of blocks: {nnode}")
    #
    # test = cfg.kb.functions[0x47e1cc]
    # nedge = len(list(test.graph.edges))
    # nnod = len(list(test.graph.nodes))

    # a random number
    global time_addr
    time_addr = 0x1f34ff80
    time_var = {
            "name": "time",
            "address": 0x1f34ff80,
            "size": 4,
            "sort": "int",
            "type": "time"
        }

    # import ipdb; ipdb.set_trace()
    proj.hook_symbol('_ZN6AP_HAL6millisEv', millis())
    proj.hook_symbol('_ZN6AP_HAL8micros64Ev', millis())
    proj.hook_symbol('_ZN9AP_Logger11Write_EventE8LogEvent', WriteEvent())
    proj.hook_symbol('abs', abs())




    ret_trap = 0x1f32ff40
    # ret_trap1 = 0x1f32ff80

    copter_constructor_addr = 0x4604d4
    # init_rc_in_addr = 0x48c606
    # allocate_motors = 0x48f07a
    # constructor_addr = 0x472ca2     # Mode::Mode()
    mode_constructor_addr = 0x4601b2     # ModeFlip::ModeFlip()
    init_addr = 0x47df04    # ModeFlip::init()
    run_addr = 0x47e1cc    # ModeFLip::run()

    copter_addr = 0x8f1a00
    mode_flip_addr = copter_addr + 0x8188   # 0x8f9b88
    ahrs_addr = copter_addr + 0x2480
    motors_addr = 0xc00042f0  # [copter_addr + 0x5cf0]
    channel_roll_addr = 0x980000
    channel_pitch_addr = 0x981000

    func_args = {'rdi': mode_flip_addr}
    # symbolic
    channel_roll_var = claripy.BVS('channel_roll', 16)
    channel_pitch_var = claripy.BVS('channel_pitch', 16)

    # concrete, explore later
    # channel_roll_var = claripy.BVV(0, 16)
    # channel_pitch_var = claripy.BVV(0, 16)


    init_variables = {
        channel_roll_var: (channel_roll_addr + 0xc, "int", 2),
        channel_pitch_var: (channel_pitch_addr + 0xc, "int", 2)
    }

    # run the state initializer
    blank = proj.factory.blank_state(addr=copter_constructor_addr, add_options={ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.SIMPLIFY_CONSTRAINTS})
    blank.regs.rbp = 0x920000
    blank.regs.rdi = copter_addr
    blank.regs.rsi = 0x951000
    print("copter constructor")
    copter_state = call_one_func(blank)

    # initialize RC_Channel
    blank = copter_state[0].copy()
    blank.memory.store(copter_addr + 0x5500, claripy.BVV(channel_roll_addr, 64), endness=proj.arch.memory_endness)
    blank.memory.store(copter_addr + 0x5508, claripy.BVV(channel_pitch_addr, 64), endness=proj.arch.memory_endness)
    # set channel value
    blank.memory.store(channel_roll_addr + 0xc, channel_roll_var, endness=proj.arch.memory_endness)
    blank.memory.store(channel_pitch_addr + 0xc, channel_pitch_var, endness=proj.arch.memory_endness)
    rc_state = blank
    # import ipdb; ipdb.set_trace()

    # initialize motors
    blank = rc_state.copy()
    print("allocate_motors")
    blank.regs.rip = 0x49473b   # line 452
    # mov  [rbp+this], rdi
    blank.memory.store(blank.regs.rbp-0x38, claripy.BVV(copter_addr, 64), endness=proj.arch.memory_endness)
    simgr = proj.factory.simgr(blank)
    while simgr.active:
        # print(simgr.active)
        s = simgr.active[0]
        if s.addr == 0x494959:
            # import ipdb; ipdb.set_trace()
            break
        simgr.step()

    motor_state = simgr.active[0]

    # initialize attitude control
    blank = motor_state.copy()
    print("allocate attitude control")
    blank.regs.rip = 0x494a8d   # line 524
    simgr = proj.factory.simgr(blank)
    while simgr.active:
        # print(simgr.active)
        s = simgr.active[0]
        if s.addr == 0x494b1f:
            # import ipdb; ipdb.set_trace()
            break
        simgr.step()
    # import ipdb; ipdb.set_trace()
    att_state = simgr.active[0]

    blank = att_state.copy()
    blank.regs.rip = mode_constructor_addr
    print("mode constructor")
    mode_state = call_one_func(blank)


     # 
    blank = mode_state[0].copy()
    blank.regs.rip = init_addr
    blank.regs.rdi = mode_flip_addr
    blank.regs.rsi = 1
    print("modeflip init")
    initial_states = call_one_func(blank)       # here should be 4 states

    # # explore init function and set channel_pitch and channel_roll as input variables
    # # import ipdb; ipdb.set_trace()
    # state_graph = networkx.DiGraph()
    #
    # init_state_init = mode_state[0].copy()
    # init_state_init.memory.store(motors_addr + 0x80, claripy.BVV(1, 8), endness=init_state_init.project.arch.memory_endness)
    # init_func = init_addr
    # init_state_init.regs.rdi = mode_flip_addr
    #
    # # what are output variables in this case? `throttle_out` is a local variable
    # fields_desc = {
    #     'state': (mode_flip_addr + 0x84, "byte", 1),
    #     # 'channel_roll': (channel_roll_addr + 0xc, "int", 2),
    #     # 'channel_pitch': (channel_pitch_addr + 0xc, "int", 2),
    #     # 'roll_dir': (mode_flip_addr + 0x8c, "byte", 1),        #  0x8f9c14
    #     # 'pitch_dir': (mode_flip_addr + 0x8d, "byte", 1),
    #     'throttle': (motors_addr + 0x28, "double", 4),
    #     'roll_sensor': (ahrs_addr + 0x394, "int", 4)
    # }
    #
    # fields = state_graph_recovery.AbstractStateFields(fields_desc)

    # init_sgr = proj.analyses.StateGraphRecovery(init_func, fields, "arduino", time_addr=time_addr, rollsensor_addr = channel_pitch_addr+0xc,
    #                                             init_state=init_state_init, init_variables=init_variables,
    #                                             state_id_addr = 0x8f9c15, state_graph = state_graph)

    # import ipdb; ipdb.set_trace()

    # proj.hook_symbol('sinf', sinf())
    # proj.hook_symbol('cosf', cosf())
    proj.hook_symbol('_Z7is_zerof', is_zero())

    # make sure init function returns true
    for s in initial_states:
        if s.solver.eval(s.regs.eax) == 0:
            continue
        else:

            # import ipdb; ipdb.set_trace()
            initial_state = s
            initial_state = initial_states[4]   # roll right

            print(initial_state.memory.load(0x8f9c14,1)) # roll_dir
            print(initial_state.memory.load(0x8f9c15, 1)) # pitch_dir
            init_time = time.time()
            print("------------init time: %s ----------" % (init_time - start_time))

            fields_desc = {
                'state': (mode_flip_addr + 0x84, "byte", 1),
                # 'channel_roll': (channel_roll_addr + 0xc, "int", 2),
                # 'channel_pitch': (channel_pitch_addr + 0xc, "int", 2),
                # 'roll_dir': (mode_flip_addr + 0x8c, "byte", 1),        #  0x8f9c14
                # 'pitch_dir': (mode_flip_addr + 0x8d, "byte", 1),
                'throttle': (motors_addr + 0x28, "double", 4),
                'roll_sensor': (ahrs_addr + 0x394, "int", 4)
            }

            fields = state_graph_recovery.AbstractStateFields(fields_desc)
            # func = proj.kb.functions['_ZN8ModeFlip3runEv']
            func = 0x47e1cc
            initial_state.regs.rdi = mode_flip_addr
            sgr = proj.analyses.StateGraphRecovery(func, fields, "arduino", time_var, rollsensor_addr = ahrs_addr + 0x394,
                                                   init_state=initial_state, init_variables=init_variables, func_args=func_args, state_id_addr = mode_flip_addr+0x84)
            sgr_time = time.time()
            print("------------sgr time: %s ----------" % (sgr_time - init_time))
            # pickle.dumps(sgr, -1)
            # output the graph to a dot file
            from networkx.drawing.nx_agraph import write_dot
            write_dot(sgr.state_graph, "graphs/rollr.dot")
            print(f"[INFO] After SGR: #Node {sgr.state_graph.number_of_nodes()}, #Edge {sgr.state_graph.number_of_edges()}")
            import ipdb; ipdb.set_trace()


            # verify rule
            finder = RuleVerifier(sgr.state_graph)
            rule_start_time = time.time()
            rule = TimeoutAbandon(2500)
            r, src, dst = finder.verify(rule)

            rule1_time = time.time()
            print("------------rule1 time: %s ----------" % (rule1_time - rule_start_time))

            rule = Abandon0Throttle()
            r, src, dst = finder.verify(rule)
            rule2_time = time.time()
            print("------------rule2 time: %s ----------" % (rule2_time - rule1_time))

            rule3 = NoFlipBelow10m()
            r, src, dst = finder.verify(rule3)

            return


if __name__ == "__main__":

    binary_path = "../../artifacts/binaries/arducopter"
    variable_path = ""

    test_flip(binary_path, variable_path)

