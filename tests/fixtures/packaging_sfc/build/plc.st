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


PROGRAM lamp
  VAR
    start_button : BOOL := False;
    red_light : BOOL;
    conveyor_motor : BOOL := False;
    product_sensor : BOOL := False;
    product_empty_sensor : BOOL := False;
    green_light : BOOL := False;
    yellow_light : BOOL := False;
    product_valve : BOOL := False;
    stop : BOOL;
  END_VAR

  INITIAL_STEP Start:
    red_light(N);
    conveyor_motor(R);
    yellow_light(R);
    green_light(R);
  END_STEP

  TRANSITION FROM Start TO Conveyor_Start
    := start_button;
  END_TRANSITION

  STEP Conveyor_Start:
    conveyor_motor(N);
    red_light(R);
    green_light(N);
  END_STEP

  TRANSITION FROM Conveyor_Start TO Product_Detected
    := product_sensor;
  END_TRANSITION

  STEP Product_Detected:
    conveyor_motor(R);
    green_light(R);
    red_light(N);
  END_STEP

  TRANSITION FROM Product_Detected TO Package
    := product_empty_sensor;
  END_TRANSITION

  STEP Package:
    product_valve(N);
    yellow_light(N);
    stop(D, T#25s);
  END_STEP

  TRANSITION FROM Package TO Stop_Packaging
    := stop;
  END_TRANSITION

  STEP Stop_Packaging:
    product_valve(R);
    yellow_light(R);
  END_STEP

  TRANSITION FROM Stop_Packaging TO Conveyor_Start
    := start_button;
  END_TRANSITION

END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#20ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : lamp;
  END_RESOURCE
END_CONFIGURATION
