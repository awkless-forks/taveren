TYPE
  LOGLEVEL : (CRITICAL, WARNING, INFO, DEBUG) := INFO;
END_TYPE

FUNCTION_BLOCK LOGGER
  VAR_INPUT
    TRIG : BOOL;
    MSG : STRING;
    LEVEL : LOGLEVEL := INFO;
  END_VAR
  VAR
    TRIG0 : BOOL;
  END_VAR

  IF TRIG AND NOT TRIG0 THEN
  {{
   LogMessage(GetFbVar(LEVEL),(char*)GetFbVar(MSG, .body),GetFbVar(MSG, .len));
  }}
  END_IF;
  TRIG0:=TRIG;
END_FUNCTION_BLOCK


PROGRAM lift
  VAR
    assigned_pallet_rack : SINT := 6;
    lift_up_motor : BOOL;
    lift_down_motor : BOOL;
    conveyor_motor : BOOL;
    current_rack : SINT := 0;
    initial_rack : SINT := 0;
    TON0 : TON;
    TON1 : TON;
    _TMP_GT5_OUT : BOOL;
    _TMP_EQ12_OUT : BOOL;
    _TMP_EQ23_OUT : BOOL;
  END_VAR

  INITIAL_STEP Initialize:
    lift_up_motor(R);
    lift_down_motor(R);
    conveyor_motor(R);
    COMPUTE_FUNCTION_BLOCKS(S);
  END_STEP

  ACTION COMPUTE_FUNCTION_BLOCKS:
    _TMP_GT5_OUT := GT(assigned_pallet_rack, current_rack);
    _TMP_EQ12_OUT := EQ(assigned_pallet_rack, current_rack);
    TON0(IN := conveyor_motor, PT := T#5s);
    _TMP_EQ23_OUT := EQ(current_rack, initial_rack);
    TON1(IN := conveyor_motor, PT := T#5s);
  END_ACTION

  TRANSITION FROM Initialize TO Go_Up
    := _TMP_GT5_OUT;
  END_TRANSITION

  STEP Go_Up:
    lift_up_motor(N);
  END_STEP

  TRANSITION FROM Go_Up TO Deliver_Box
    := _TMP_EQ12_OUT;
  END_TRANSITION

  INITIAL_STEP Deliver_Box:
    lift_up_motor(R);
    conveyor_motor(N);
  END_STEP

  TRANSITION FROM Deliver_Box TO Go_Down
    := TON0.Q;
  END_TRANSITION

  STEP Go_Down:
    lift_down_motor(N);
  END_STEP

  TRANSITION FROM Go_Down TO Get_Box
    := _TMP_EQ23_OUT;
  END_TRANSITION

  INITIAL_STEP Get_Box:
    lift_down_motor(R);
    conveyor_motor(N);
  END_STEP

  TRANSITION FROM Get_Box TO Go_Up
    := TON1.Q;
  END_TRANSITION

END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#20ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : lift;
  END_RESOURCE
END_CONFIGURATION
