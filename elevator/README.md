This folder contains the analysis code for elevator (Elev.1 and Elev.2).

[`state_graph_recovery`](state_graph_recovery/) is the library for FSM recovery and policy verification.  
[`test`](test/) contains test files.  
[`graphs`](test/graphs/) contains the generated FSMs.

To start the analysis, in `test` folder run `python test_elevator.py [ARM|AVR]`.

To analyze Elev.2 (AVR8), you will need use the angr extension for AVR symbolic execution support: in your angr directory, run `git checkout feat/avr`.