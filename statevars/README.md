# State variable identification

run `python -m statevars`

Heuristics:
1. A state variable stays alive across scan cycles, so it must
be stored in non-volatile regions such as global sections or
on the heap. A state variable cannot be stored on the stack
frame of any scan cycle functions.
2. State variables are used in branch conditionals to impact the
internal state by determining the code to run.
3. In each scan cycle, a state variables must be used first before
it is updated (i.e., assigned a new value to). This is different
from local variables that must be assigned values before they
are used.


