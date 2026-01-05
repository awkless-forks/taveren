"""
This script is to evaluate the reduction of state space during FSM recovery (Appendix F).
"""

import angr
import claripy
import logging

binary_path = '../artifacts/Traffic_Light_original/build/Traffic_Light_original.so'   #T9   0x42C034
variable_path = '../traffic_lights/test/original.so'

def _hook_py_extensions(proj, cfg):
    proj.hook(cfg.kb.functions['PYTHON_EVAL_body__'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['PYTHON_POLL_body__'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['__publish_debug'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['__publish_py_ext'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())



if __name__ == '__main__':
    proj = angr.Project(binary_path, load_options={'auto_load_libs': False})
    cfg = proj.analyses.CFG()

    _hook_py_extensions(proj, cfg)
    scan_cycle_function_addr = 0x42C034
    # run the state initializer
    init = cfg.kb.functions['config_init__']
    init_callable = proj.factory.callable(init.addr, perform_merge=False)
    init_callable.perform_call()
    initial_state = init_callable.result_state
    # import ipdb; ipdb.set_trace()
    initial_state.ip = scan_cycle_function_addr  # initialize your state at the correct execution address
    ret_trap = 0x1f32ff40

    if initial_state.project.arch.call_pushes_ret:
        initial_state.stack_push(claripy.BVV(ret_trap, initial_state.project.arch.bits))


    simgr = proj.factory.simgr(initial_state)
    simgr.stashes["cycle_done"] = []

    state_counter = 0
    while simgr.active or simgr.cycle_done:
        print(simgr.active)
        for state in simgr.cycle_done:
            # import ipdb; ipdb.set_trace()
            if state.addr == ret_trap:
                state.ip = scan_cycle_function_addr
                state.stack_push(claripy.BVV(ret_trap, state.project.arch.bits))
            simgr.stashes["active"] = simgr.cycle_done
            simgr.stashes["cycle_done"] = []

        # while simgr.active:
        if len(simgr.active) > 1:
            import ipdb; ipdb.set_trace()
        simgr.step()
        state_counter += len(simgr.active)
        simgr.stash(filter_func=lambda path: len(path.history.bbl_addrs) > 10000, to_stash="dropped")
        simgr.stash(filter_func=lambda path: path.addr == ret_trap, to_stash="cycle_done")
        print(state_counter)

    print("final state count: ", state_counter)
    # import ipdb; ipdb.set_trace()