This folder contains the analysis code for Launch Abort system (Abort.1~3).

[`state_graph_recovery`](state_graph_recovery/) is the library for FSM recovery and policy verification.  
[`test`](test/) contains test files.  
[`graphs`](test/graphs/) contains the generated FSMs.

To start the analysis, in `test` folder, run `python test_abort.py [modelogic|abortlogic|full]`