"""Ta'veren: find blind-trust vulnerabilities in PLC binaries via state machine recovery.

Ta'veren recovers the finite state machine (FSM) implemented by a PLC program from its binary, then
checks safety policies against it. The workflow is:

1. Find the scan cycle function (:mod:`taveren.scan_cycle`), the initialization function
   (:mod:`taveren.init_finder`) and the state variables (:mod:`taveren.statevars`). These are also
   available as the ``taveren-scan-cycle``, ``taveren-init-finder`` and ``taveren-statevars``
   commands.
2. Describe the program's inputs, outputs and state variables in an environment model, and turn
   it into :class:`AbstractStateFields` (:mod:`taveren.env_model`).
3. Recover the state graph with an analysis built on :class:`StateGraphRecoveryBase`
   (:mod:`taveren.state_graph_recovery`).
4. Write safety policies as rules (:mod:`taveren.rule_verifier`) and check them with
   :class:`RuleVerifier`.
5. Trace violations to their root causes with :class:`RootCauseAnalysis` and patch them
   (:mod:`taveren.apis`).

Importing this package applies the angr patches in :mod:`taveren.angr_compat`.

Examples:
    Check a policy against a recovered state graph. Nodes are abstract states, tuples of
    ``(field, value)`` pairs; edges carry the ``time_delta`` of the transition in seconds:

    >>> import networkx
    >>> from taveren import IllegalNodeBaseRule, RuleVerifier
    >>> graph = networkx.DiGraph()
    >>> graph.add_edge((("MOTOR", 0), ("VALVE", 1)), (("MOTOR", 1), ("VALVE", 0)), time_delta=10)
    >>> class NoBothOn(IllegalNodeBaseRule):
    ...     def verify_node(self, graph, node):
    ...         return not (dict(node)["MOTOR"] and dict(node)["VALVE"])
    >>> safe, _, _ = RuleVerifier(graph).verify(NoBothOn())
    >>> safe
    True

    The full pipeline on the one-sensor water tank, as in
    ``tests/water_tank_one_sensor/test_water_tank_one_sensor.py`` (which defines the
    ``StateGraphRecoveryOneSensor`` analysis and the ``SensorExclusionRule`` policy):

    >>> import angr, json
    >>> from taveren import AbstractStateFields, generate_field_desc, hook_py_extensions
    >>> proj = angr.Project("tests/fixtures/water_tank_sfc_one_sensor/build/water_tank_sfc_one_sensor.so",
    ...                     auto_load_libs=False)  # doctest: +SKIP
    >>> cfg = proj.analyses.CFG()  # doctest: +SKIP
    >>> hook_py_extensions(proj, cfg)  # doctest: +SKIP
    >>> init = proj.factory.callable(cfg.kb.functions["config_init__"].addr,
    ...                              perform_merge=False)  # doctest: +SKIP
    >>> init.perform_call()  # doctest: +SKIP
    >>> env = json.load(open("tests/water_tank_one_sensor/water_tank.json"))  # doctest: +SKIP
    >>> outputs, inputs = generate_field_desc(env)  # doctest: +SKIP
    >>> sgr = proj.analyses.StateGraphRecoveryOneSensor(
    ...     cfg.kb.functions["__run"], AbstractStateFields(outputs), env["software"],
    ...     int(env["time_addr"], 16), init_state=init.result_state,
    ...     inputs=inputs, fields_input=AbstractStateFields(inputs))  # doctest: +SKIP
    >>> safe, src, dst = RuleVerifier(sgr.state_graph).verify(SensorExclusionRule())  # doctest: +SKIP
"""

# Re-apply the patches from our former angr/claripy forks before anything else.
from . import angr_compat
from .abstract_state import AbstractStateFields
from .rule_verifier import (
    MinDelayBaseRule,
    RuleVerifier,
    IllegalNodeBaseRule,
    IllegalTransitionBaseRule,
    MaxDelayBaseRule,
    BaseRule,
)
from .root_cause import RootCauseAnalysis
from .state_graph_recovery import StateGraphRecoveryBase
from .env_model import generate_field_desc, generate_output_config_desc
from .hooks import hook_py_extensions, normalize_timespec
