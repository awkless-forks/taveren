TYPE
  datatype0 : BOOL;
END_TYPE

PROGRAM water_tank_sfc
  VAR
    low_level_sensor : SINT := 15;
    high_level_sensor : SINT := 85;
    motor : BOOL := False;
    water_level : SINT := 50;
  END_VAR

  INITIAL_STEP Initialize:
    motor(R);
  END_STEP

  TRANSITION FROM Initialize TO Fill_Tank
    := water_level < 15;
  END_TRANSITION

  STEP Fill_Tank:
    motor(N);
  END_STEP

  TRANSITION FROM Fill_Tank TO Stop_Motor
    := water_level > 85;
  END_TRANSITION

  STEP Stop_Motor:
    motor(R);
  END_STEP

  TRANSITION FROM Stop_Motor TO Fill_Tank
    := water_level < 15;
  END_TRANSITION

END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#20ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : water_tank_sfc;
  END_RESOURCE
END_CONFIGURATION
