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
