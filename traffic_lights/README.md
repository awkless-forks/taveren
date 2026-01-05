This folder contains the analysis code for traffic lights (TL.4~11) and oven (Oven.1).

[`state_graph_recovery`](state_graph_recovery/) is the library for FSM recovery and policy verification.  
[`test`](test/) contains test files.  
[`graphs`](test/graphs/) contains the generated FSMs.

To start the analysis for traffic lights TL.4-10, in `test` folder, run `python test_trafficlight.py [4-10]`

To start the analysis for traffic light TL.11, in `test` folder, run `python test_simulinklights.py`

To start the analysis for oven Oven.1, in `test` folder, run `python test_oven.py`