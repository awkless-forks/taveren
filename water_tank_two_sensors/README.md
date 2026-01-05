This folder contains the analysis code for water tank with two sensors (WT.1 and WT.3).

[`state_graph_recovery`](state_graph_recovery/) is the library for FSM recovery and policy verification.  
[`test`](test/) contains test files.  
[`graphs`](test/graphs/) contains the generated FSMs.

To start the analysis, in `test` folder, run `python test_water_tank.py [WT1|WT3]`