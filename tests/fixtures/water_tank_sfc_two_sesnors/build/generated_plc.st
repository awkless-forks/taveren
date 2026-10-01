PROGRAM water_tank_sfc
  VAR
    low_level_sensor : BOOL := False;
    high_level_sensor : BOOL := False;
    pump : BOOL := False;
  END_VAR

  INITIAL_STEP Initialize:
    pump(R);
  END_STEP

  TRANSITION FROM Initialize TO Fill_Tank
    := low_level_sensor;
  END_TRANSITION

  STEP Fill_Tank:
    pump(N);
  END_STEP

  TRANSITION FROM Fill_Tank TO Stop_Motor
    := high_level_sensor;
  END_TRANSITION

  STEP Stop_Motor:
    pump(R);
  END_STEP

  TRANSITION FROM Stop_Motor TO Fill_Tank
    := low_level_sensor;
  END_TRANSITION

END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#20ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : water_tank_sfc;
  END_RESOURCE
END_CONFIGURATION
