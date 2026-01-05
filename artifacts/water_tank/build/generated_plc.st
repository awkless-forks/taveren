PROGRAM Water_Tank
  VAR
    low_level_sensor : BOOL;
    pump : BOOL;
    high_level_sensor : BOOL;
    SR0 : SR;
  END_VAR

  SR0(S1 := low_level_sensor, R := high_level_sensor);
  pump := SR0.Q1;
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#20ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : Water_Tank;
  END_RESOURCE
END_CONFIGURATION
