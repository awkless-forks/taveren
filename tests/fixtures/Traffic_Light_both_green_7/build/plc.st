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



FUNCTION_BLOCK python_eval
  VAR_INPUT
    TRIG : BOOL;
    CODE : STRING;
  END_VAR
  VAR_OUTPUT
    ACK : BOOL;
    RESULT : STRING;
  END_VAR
  VAR
    STATE : DWORD;
    BUFFER : STRING;
    PREBUFFER : STRING;
    TRIGM1 : BOOL;
    TRIGGED : BOOL;
  END_VAR

  {extern void __PythonEvalFB(int, PYTHON_EVAL*);__PythonEvalFB(0, data__);}
END_FUNCTION_BLOCK

FUNCTION_BLOCK python_poll
  VAR_INPUT
    TRIG : BOOL;
    CODE : STRING;
  END_VAR
  VAR_OUTPUT
    ACK : BOOL;
    RESULT : STRING;
  END_VAR
  VAR
    STATE : DWORD;
    BUFFER : STRING;
    PREBUFFER : STRING;
    TRIGM1 : BOOL;
    TRIGGED : BOOL;
  END_VAR

  {extern void __PythonEvalFB(int, PYTHON_EVAL*);__PythonEvalFB(1,(PYTHON_EVAL*)(void*)data__);}
END_FUNCTION_BLOCK

FUNCTION_BLOCK python_gear
  VAR_INPUT
    N : UINT;
    TRIG : BOOL;
    CODE : STRING;
  END_VAR
  VAR_OUTPUT
    ACK : BOOL;
    RESULT : STRING;
  END_VAR
  VAR
    py_eval : python_eval;
    COUNTER : UINT;
    _TMP_ADD10_OUT : UINT;
    _TMP_EQ13_OUT : BOOL;
    _TMP_SEL15_OUT : UINT;
    _TMP_AND7_OUT : BOOL;
  END_VAR

  _TMP_ADD10_OUT := ADD(COUNTER, 1);
  _TMP_EQ13_OUT := EQ(N, _TMP_ADD10_OUT);
  _TMP_SEL15_OUT := SEL(_TMP_EQ13_OUT, _TMP_ADD10_OUT, 0);
  COUNTER := _TMP_SEL15_OUT;
  _TMP_AND7_OUT := AND(_TMP_EQ13_OUT, TRIG);
  py_eval(TRIG := _TMP_AND7_OUT, CODE := CODE);
  ACK := py_eval.ACK;
  RESULT := py_eval.RESULT;
END_FUNCTION_BLOCK



FUNCTION_BLOCK GetBoolString
  VAR_INPUT
    VALUE : BOOL;
  END_VAR
  VAR_OUTPUT
    CODE : STRING;
  END_VAR

  IF VALUE THEN
    CODE := 'True';
  ELSE
    CODE := 'False';
  END_IF;
END_FUNCTION_BLOCK

FUNCTION_BLOCK Button
  VAR
    ID : STRING;
  END_VAR
  VAR_INPUT
    back_id : STRING;
    sele_id : STRING;
    toggle : BOOL;
    set_state : BOOL;
    state_in : BOOL;
  END_VAR
  VAR_OUTPUT
    state_out : BOOL;
  END_VAR
  VAR
    init_Command : python_eval;
    GetButtonState : GetBoolString;
    setstate_Command : python_eval;
    getstate_Command : python_poll;
    GetButtonToggle : GetBoolString;
    _TMP_CONCAT2_OUT : STRING;
    _TMP_CONCAT22_OUT : STRING;
    _TMP_STRING_TO_INT25_OUT : INT;
    _TMP_INT_TO_BOOL26_OUT : BOOL;
    _TMP_AND31_OUT : BOOL;
    _TMP_CONCAT7_OUT : STRING;
  END_VAR

  GetButtonToggle(VALUE := toggle);
  _TMP_CONCAT2_OUT := CONCAT('createSVGUIControl("button",back_id="', back_id, '",sele_id="', sele_id, '",toggle=', GetButtonToggle.CODE, ',active=True)');
  init_Command(TRIG := BOOL#1, CODE := _TMP_CONCAT2_OUT);
  ID := init_Command.RESULT;
  _TMP_CONCAT22_OUT := CONCAT('int(getAttr(', ID, ',"state",False))');
  getstate_Command(TRIG := init_Command.ACK, CODE := _TMP_CONCAT22_OUT);
  _TMP_STRING_TO_INT25_OUT := STRING_TO_INT(getstate_Command.RESULT);
  _TMP_INT_TO_BOOL26_OUT := INT_TO_BOOL(_TMP_STRING_TO_INT25_OUT);
  state_out := _TMP_INT_TO_BOOL26_OUT;
  _TMP_AND31_OUT := AND(init_Command.ACK, set_state);
  GetButtonState(VALUE := state_in);
  _TMP_CONCAT7_OUT := CONCAT('setAttr(', ID, ',"state",', GetButtonState.CODE, ')');
  setstate_Command(TRIG := _TMP_AND31_OUT, CODE := _TMP_CONCAT7_OUT);
END_FUNCTION_BLOCK

FUNCTION_BLOCK Led
  VAR
    ID : STRING;
  END_VAR
  VAR_INPUT
    back_id : STRING;
    sele_id : STRING;
    state_in : BOOL;
  END_VAR
  VAR
    init_Command : python_eval;
    setstate_Command : python_poll;
    GetLedState : GetBoolString;
    _TMP_CONCAT2_OUT : STRING;
    _TMP_CONCAT7_OUT : STRING;
  END_VAR

  _TMP_CONCAT2_OUT := CONCAT('createSVGUIControl("button",back_id="', back_id, '",sele_id="', sele_id, '",toggle=True,active=False)');
  init_Command(TRIG := BOOL#1, CODE := _TMP_CONCAT2_OUT);
  ID := init_Command.RESULT;
  GetLedState(VALUE := state_in);
  _TMP_CONCAT7_OUT := CONCAT('setAttr(', ID, ',"state",', GetLedState.CODE, ')');
  setstate_Command(TRIG := init_Command.ACK, CODE := _TMP_CONCAT7_OUT);
END_FUNCTION_BLOCK

FUNCTION_BLOCK TextCtrl
  VAR
    ID : STRING;
  END_VAR
  VAR_INPUT
    back_id : STRING;
    set_text : BOOL;
    text : STRING;
  END_VAR
  VAR
    SVGUI_TEXTCTRL : python_eval;
    setstate_Command : python_eval;
    _TMP_CONCAT1_OUT : STRING;
    _TMP_AND31_OUT : BOOL;
    _TMP_CONCAT12_OUT : STRING;
  END_VAR

  _TMP_CONCAT1_OUT := CONCAT('createSVGUIControl("textControl", back_id="', back_id, '")');
  SVGUI_TEXTCTRL(TRIG := BOOL#1, CODE := _TMP_CONCAT1_OUT);
  ID := SVGUI_TEXTCTRL.RESULT;
  _TMP_AND31_OUT := AND(SVGUI_TEXTCTRL.ACK, set_text);
  _TMP_CONCAT12_OUT := CONCAT('setAttr(', ID, ',"text","', text, '")');
  setstate_Command(TRIG := _TMP_AND31_OUT, CODE := _TMP_CONCAT12_OUT);
END_FUNCTION_BLOCK


FUNCTION_BLOCK traffic_light_sequence
  VAR_INPUT
    SWITCH_BUTTON : BOOL;
    PEDESTRIAN_BUTTON : BOOL;
  END_VAR
  VAR_OUTPUT
    RED_LIGHT : BOOL;
    ORANGE_LIGHT : BOOL;
    GREEN_LIGHT : BOOL;
    PEDESTRIAN_RED_LIGHT : BOOL;
    PEDESTRIAN_GREEN_LIGHT : BOOL;
  END_VAR
  VAR
    TON1 : TON;
    TON2 : TON;
    ALLOW_CARS : BOOL;
    WARN_CARS : BOOL;
    STOP_CARS : BOOL;
    ALLOW_PEDESTRIANS : BOOL;
    STOP_PEDESTRIANS : BOOL;
    TON3 : TON;
    R_TRIG0 : R_TRIG;
    R_TRIG1 : R_TRIG;
    SR0 : SR;
    _TMP_NOT42_OUT : BOOL;
    _TMP_OR35_OUT : BOOL;
  END_VAR

  INITIAL_STEP Standstill:
    STANDSTILL_INLINE1(P);
    BLINK_ORANGE_LIGHT(N);
    PEDESTRIAN_RED_LIGHT(R);
    PEDESTRIAN_GREEN_LIGHT(R);
    RED_LIGHT(R);
    GREEN_LIGHT(R);
    COMPUTE_FUNCTION_BLOCKS(S);
  END_STEP

  ACTION STANDSTILL_INLINE1:
    ORANGE_LIGHT := 1;
  END_ACTION

  ACTION BLINK_ORANGE_LIGHT:
    TON1(IN := NOT(ORANGE_LIGHT), PT := T#500ms);
    R_TRIG1(CLK := TON1.Q);
    IF R_TRIG1.Q THEN
      ORANGE_LIGHT := TRUE; (*set*)
    END_IF;
    TON2(IN := ORANGE_LIGHT, PT := T#500ms);
    R_TRIG0(CLK := TON2.Q);
    IF R_TRIG0.Q THEN
      ORANGE_LIGHT := FALSE; (*reset*)
    END_IF;
  END_ACTION

  ACTION COMPUTE_FUNCTION_BLOCKS:
    _TMP_NOT42_OUT := NOT(SWITCH_BUTTON);
    SR0(S1 := PEDESTRIAN_BUTTON, R := TON3.Q);
    TON3(IN := SR0.Q1, PT := T#2s);
    _TMP_OR35_OUT := OR(TON3.Q, WARN_CARS);
  END_ACTION

  TRANSITION FROM Standstill TO ORANGE
    := SWITCH_BUTTON;
  END_TRANSITION

  STEP ORANGE:
    GREEN_LIGHT(R);
    ORANGE_LIGHT(S);
    PEDESTRIAN_RED_LIGHT(S);
    STOP_CARS(D, T#2s);
  END_STEP

  TRANSITION FROM ORANGE TO RED
    := STOP_CARS;
  END_TRANSITION

  STEP RED:
    ORANGE_LIGHT(R);
    RED_LIGHT(S);
    ALLOW_PEDESTRIANS(D, T#2s);
  END_STEP

  TRANSITION FROM RED TO PEDESTRIAN_GREEN
    := ALLOW_PEDESTRIANS;
  END_TRANSITION

  STEP PEDESTRIAN_GREEN:
    PEDESTRIAN_RED_LIGHT(S);
    PEDESTRIAN_GREEN_LIGHT(R);
    STOP_PEDESTRIANS(D, T#10s);
  END_STEP

  TRANSITION FROM PEDESTRIAN_GREEN TO PEDESTRIAN_RED
    := STOP_PEDESTRIANS;
  END_TRANSITION

  STEP PEDESTRIAN_RED:
    PEDESTRIAN_GREEN_LIGHT(S);
    PEDESTRIAN_RED_LIGHT(R);
    ALLOW_CARS(D, T#2s);
  END_STEP

  TRANSITION FROM PEDESTRIAN_RED TO GREEN
    := ALLOW_CARS;
  END_TRANSITION

  STEP GREEN:
    GREEN_LIGHT(S);
    RED_LIGHT(R);
    WARN_CARS(D, T#20s);
  END_STEP

  TRANSITION FROM GREEN TO Standstill
    := NOT SWITCH_BUTTON;
  END_TRANSITION

  TRANSITION FROM GREEN TO ORANGE
    := _TMP_OR35_OUT;
  END_TRANSITION

  TRANSITION FROM PEDESTRIAN_RED TO Standstill
    := NOT(SWITCH_BUTTON);
  END_TRANSITION

  TRANSITION FROM PEDESTRIAN_GREEN TO Standstill
    := NOT SWITCH_BUTTON;
  END_TRANSITION

  TRANSITION FROM RED TO Standstill
    := _TMP_NOT42_OUT;
  END_TRANSITION

  TRANSITION FROM ORANGE TO Standstill
    := _TMP_NOT42_OUT;
  END_TRANSITION

END_FUNCTION_BLOCK

PROGRAM main_program
  VAR
    trafic_light_sequence0 : traffic_light_sequence;
    SwitchButton : Button;
    PedestrianButton : Button;
    RedLight : Led;
    OrangeLight : Led;
    GreenLight : Led;
    PedestrianRedLight : Led;
    PedestrianGreenLight : Led;
  END_VAR

  SwitchButton(back_id := 'SWITCH_OFF', sele_id := 'SWITCH_ON', toggle := 1);
  PedestrianButton(back_id := 'PEDESTRIAN_OFF', sele_id := 'PEDESTRIAN_ON');
  trafic_light_sequence0(SWITCH_BUTTON := SwitchButton.state_out, PEDESTRIAN_BUTTON := PedestrianButton.state_out);
  RedLight(back_id := 'RED_OFF', sele_id := 'RED_ON', state_in := trafic_light_sequence0.RED_LIGHT);
  OrangeLight(back_id := 'ORANGE_OFF', sele_id := 'ORANGE_ON', state_in := trafic_light_sequence0.ORANGE_LIGHT);
  GreenLight(back_id := 'GREEN_OFF', sele_id := 'GREEN_ON', state_in := trafic_light_sequence0.GREEN_LIGHT);
  PedestrianRedLight(back_id := 'PEDESTRIAN_RED_OFF', sele_id := 'PEDESTRIAN_RED_ON', state_in := trafic_light_sequence0.PEDESTRIAN_RED_LIGHT);
  PedestrianGreenLight(back_id := 'PEDESTRIAN_GREEN_OFF', sele_id := 'PEDESTRIAN_GREEN_ON', state_in := trafic_light_sequence0.PEDESTRIAN_GREEN_LIGHT);
END_PROGRAM


CONFIGURATION config

  RESOURCE resource1 ON PLC
    TASK test_task(INTERVAL := T#100ms,PRIORITY := 0);
    PROGRAM main_instance WITH test_task : main_program;
  END_RESOURCE
END_CONFIGURATION
