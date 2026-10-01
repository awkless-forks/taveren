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


PROGRAM car_wash
  VAR
    available_light : BOOL;
    conveyor_motor : BOOL := False;
    conveyor_light : BOOL := False;
    wax_light : BOOL := False;
    soap_light : BOOL := False;
    scrubbers : BOOL := False;
    scrub_light : BOOL := False;
    soap_sprinkler : BOOL := False;
    water_sprinkler : BOOL := False;
    wax_liquid : BOOL := False;
    Dryers : BOOL := False;
    car_on_start_sensor : BOOL := False;
    service_selection_button : SINT;
    wash_only_selection : SINT := 1;
    wash_and_dry_selection : SINT := 2;
    wash_dry_and_wax_selection : SINT := 3;
    A_rinse2 : BOOL := False;
    A_move_car2 : BOOL := False;
    A_soap0 : BOOL := False;
    A_move_car3 : BOOL := False;
    A_scrub0 : BOOL := False;
    A_move_car4 : BOOL := False;
    A_rinse3 : BOOL := False;
    A_move_car5 : BOOL := False;
    A_finish : BOOL := False;
    B_rinse4 : BOOL := False;
    B_move_car6 : BOOL := False;
    B_soap1 : BOOL := False;
    B_move_car7 : BOOL := False;
    B_scrub2 : BOOL := False;
    B_move_car8 : BOOL := False;
    B_rinse5 : BOOL := False;
    B_move_car9 : BOOL := False;
    B_dry0 : BOOL := False;
    B_move_car10 : BOOL := False;
    B_finish : BOOL := False;
    C_rinse6 : BOOL := False;
    C_move_car11 : BOOL := False;
    C_soap2 : BOOL := False;
    C_move_car12 : BOOL := False;
    C_scrub3 : BOOL := False;
    C_move_car13 : BOOL := False;
    C_rinse7 : BOOL := False;
    C_move_car14 : BOOL := False;
    C_dry1 : BOOL := False;
    C_move_car15 : BOOL := False;
    C_wax_liquid0 : BOOL := False;
    C_move_car16 : BOOL := False;
    C_scrub1 : BOOL := False;
    C_move_car17 : BOOL := False;
    C_finish : BOOL := False;
    _TMP_EQ14_OUT : BOOL;
    _TMP_EQ17_OUT : BOOL;
    _TMP_EQ20_OUT : BOOL;
  END_VAR

  INITIAL_STEP START:
    available_light(S);
    conveyor_light(R);
    conveyor_motor(R);
    water_sprinkler(R);
    scrubbers(R);
    wax_liquid(R);
    Dryers(R);
    car_on_start_sensor(R);
    soap_light(R);
    scrub_light(R);
    wax_light(R);
    soap_sprinkler(R);
    COMPUTE_FUNCTION_BLOCKS(S);
  END_STEP

  ACTION COMPUTE_FUNCTION_BLOCKS:
    _TMP_EQ14_OUT := EQ(service_selection_button, wash_only_selection);
    _TMP_EQ17_OUT := EQ(service_selection_button, wash_and_dry_selection);
    _TMP_EQ20_OUT := EQ(service_selection_button, wash_dry_and_wax_selection);
  END_ACTION

  TRANSITION FROM START TO Service_Selection0
    := car_on_start_sensor;
  END_TRANSITION

  STEP Service_Selection0:
    available_light(R);
  END_STEP

  TRANSITION FROM Service_Selection0 TO Wash_Only_A
    := _TMP_EQ14_OUT;
  END_TRANSITION

  STEP Wash_Only_A:
    conveyor_light(N);
    conveyor_motor(N);
    A_rinse2(D, T#10s);
  END_STEP

  TRANSITION FROM Wash_Only_A TO Rinse2
    := A_rinse2;
  END_TRANSITION

  STEP Rinse2:
    conveyor_light(R);
    water_sprinkler(N);
    conveyor_motor(R);
    A_move_car2(D, T#25s);
  END_STEP

  TRANSITION FROM Rinse2 TO Move_Car2
    := A_move_car2;
  END_TRANSITION

  STEP Move_Car2:
    conveyor_light(N);
    conveyor_motor(N);
    water_sprinkler(R);
    A_soap0(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car2 TO Soap0
    := A_soap0;
  END_TRANSITION

  STEP Soap0:
    conveyor_light(R);
    soap_sprinkler(N);
    conveyor_motor(R);
    A_move_car3(D, T#25s);
  END_STEP

  TRANSITION FROM Soap0 TO Move_Car3
    := A_move_car3;
  END_TRANSITION

  STEP Move_Car3:
    conveyor_light(N);
    conveyor_motor(N);
    soap_sprinkler(R);
    A_scrub0(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car3 TO Scrub0
    := A_scrub0;
  END_TRANSITION

  STEP Scrub0:
    conveyor_light(R);
    conveyor_motor(R);
    scrubbers(N);
    A_move_car4(D, T#25s);
  END_STEP

  TRANSITION FROM Scrub0 TO Move_Car4
    := A_move_car4;
  END_TRANSITION

  STEP Move_Car4:
    conveyor_light(N);
    conveyor_motor(N);
    soap_sprinkler(R);
    A_rinse3(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car4 TO Rinse3
    := A_rinse3;
  END_TRANSITION

  STEP Rinse3:
    conveyor_light(R);
    conveyor_motor(R);
    water_sprinkler(N);
    A_move_car5(D, T#25s);
  END_STEP

  TRANSITION FROM Rinse3 TO Move_Car_5
    := A_move_car5;
  END_TRANSITION

  STEP Move_Car_5:
    conveyor_light(N);
    conveyor_motor(N);
    soap_sprinkler(R);
    A_finish(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car_5 TO START
    := A_finish;
  END_TRANSITION

  TRANSITION FROM Service_Selection0 TO Wash_And_Dry_B
    := _TMP_EQ17_OUT;
  END_TRANSITION

  STEP Wash_And_Dry_B:
    conveyor_light(N);
    conveyor_motor(N);
    B_rinse4(D, T#10s);
  END_STEP

  TRANSITION FROM Wash_And_Dry_B TO Rinse4
    := B_rinse4;
  END_TRANSITION

  STEP Rinse4:
    conveyor_light(R);
    water_sprinkler(N);
    conveyor_motor(R);
    B_move_car6(D, T#25s);
  END_STEP

  TRANSITION FROM Rinse4 TO Move_Car6
    := B_move_car6;
  END_TRANSITION

  STEP Move_Car6:
    conveyor_light(N);
    conveyor_motor(N);
    water_sprinkler(R);
    B_soap1(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car6 TO Soap1
    := B_soap1;
  END_TRANSITION

  STEP Soap1:
    conveyor_light(R);
    soap_sprinkler(N);
    conveyor_motor(R);
    B_move_car7(D, T#25s);
  END_STEP

  TRANSITION FROM Soap1 TO Move_Car7
    := B_move_car7;
  END_TRANSITION

  STEP Move_Car7:
    conveyor_light(N);
    conveyor_motor(N);
    soap_sprinkler(R);
    B_scrub2(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car7 TO Scrub2
    := B_scrub2;
  END_TRANSITION

  STEP Scrub2:
    conveyor_light(R);
    conveyor_motor(R);
    scrubbers(N);
    B_move_car8(D, T#25s);
  END_STEP

  TRANSITION FROM Scrub2 TO Move_Car8
    := B_move_car8;
  END_TRANSITION

  STEP Move_Car8:
    conveyor_light(N);
    conveyor_motor(N);
    soap_sprinkler(R);
    B_rinse5(D, T#25s);
  END_STEP

  TRANSITION FROM Move_Car8 TO Rinse5
    := B_rinse5;
  END_TRANSITION

  STEP Rinse5:
    conveyor_light(R);
    conveyor_motor(R);
    water_sprinkler(N);
    B_move_car9(D, T#25s);
  END_STEP

  TRANSITION FROM Rinse5 TO Move_Car9
    := B_move_car9;
  END_TRANSITION

  STEP Move_Car9:
    conveyor_light(N);
    conveyor_motor(N);
    soap_sprinkler(R);
    B_dry0(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car9 TO Dry0
    := B_dry0;
  END_TRANSITION

  STEP Dry0:
    conveyor_light(R);
    conveyor_motor(R);
    Dryers(N);
    B_move_car10(D, T#25s);
  END_STEP

  TRANSITION FROM Dry0 TO Move_Car10
    := B_move_car10;
  END_TRANSITION

  STEP Move_Car10:
    conveyor_light(N);
    conveyor_motor(N);
    Dryers(R);
    B_finish(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car10 TO START
    := B_finish;
  END_TRANSITION

  TRANSITION FROM Service_Selection0 TO Wash_Dry_And_Wax_C
    := _TMP_EQ20_OUT;
  END_TRANSITION

  STEP Wash_Dry_And_Wax_C:
    conveyor_light(N);
    conveyor_motor(N);
    C_rinse6(D, T#10s);
  END_STEP

  TRANSITION FROM Wash_Dry_And_Wax_C TO Rinse6
    := C_rinse6;
  END_TRANSITION

  STEP Rinse6:
    conveyor_light(R);
    water_sprinkler(N);
    conveyor_motor(R);
    C_move_car11(D, T#25s);
  END_STEP

  TRANSITION FROM Rinse6 TO Move_Car11
    := C_move_car11;
  END_TRANSITION

  STEP Move_Car11:
    conveyor_light(N);
    conveyor_motor(N);
    water_sprinkler(R);
    C_soap2(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car11 TO Soap2
    := C_soap2;
  END_TRANSITION

  STEP Soap2:
    conveyor_light(R);
    soap_sprinkler(N);
    conveyor_motor(R);
    C_move_car12(D, T#25s);
  END_STEP

  TRANSITION FROM Soap2 TO Move_Car12
    := C_move_car12;
  END_TRANSITION

  STEP Move_Car12:
    conveyor_light(N);
    conveyor_motor(N);
    soap_sprinkler(R);
    C_scrub3(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car12 TO Scrub3
    := C_scrub3;
  END_TRANSITION

  STEP Scrub3:
    conveyor_light(R);
    conveyor_motor(R);
    scrubbers(N);
    C_move_car13(D, T#25s);
  END_STEP

  TRANSITION FROM Scrub3 TO Move_Car13
    := C_move_car13;
  END_TRANSITION

  STEP Move_Car13:
    conveyor_light(N);
    conveyor_motor(N);
    soap_sprinkler(R);
    C_rinse7(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car13 TO Rinse7
    := C_rinse7;
  END_TRANSITION

  STEP Rinse7:
    conveyor_light(R);
    conveyor_motor(R);
    water_sprinkler(N);
    C_move_car14(D, T#25s);
  END_STEP

  TRANSITION FROM Rinse7 TO Move_Car_14
    := C_move_car14;
  END_TRANSITION

  STEP Move_Car_14:
    conveyor_light(N);
    conveyor_motor(N);
    soap_sprinkler(R);
    C_dry1(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car_14 TO Dry1
    := C_dry1;
  END_TRANSITION

  STEP Dry1:
    conveyor_light(R);
    conveyor_motor(R);
    Dryers(N);
    C_move_car15(D, T#25s);
  END_STEP

  TRANSITION FROM Dry1 TO Move_Car_15
    := C_move_car15;
  END_TRANSITION

  STEP Move_Car_15:
    conveyor_light(N);
    conveyor_motor(N);
    Dryers(R);
    C_wax_liquid0(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car_15 TO Wax_Liquid0
    := C_wax_liquid0;
  END_TRANSITION

  STEP Wax_Liquid0:
    conveyor_light(R);
    conveyor_motor(R);
    wax_liquid(N);
    C_move_car16(D, T#10s);
  END_STEP

  TRANSITION FROM Wax_Liquid0 TO Move_Car_16
    := C_move_car16;
  END_TRANSITION

  STEP Move_Car_16:
    conveyor_light(N);
    conveyor_motor(N);
    wax_liquid(R);
    C_scrub1(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car_16 TO Scrub1
    := C_scrub1;
  END_TRANSITION

  STEP Scrub1:
    conveyor_light(R);
    conveyor_motor(R);
    scrubbers(N);
    C_move_car17(D, T#25s);
  END_STEP

  TRANSITION FROM Scrub1 TO Move_Car_17
    := C_move_car17;
  END_TRANSITION

  STEP Move_Car_17:
    conveyor_light(N);
    conveyor_motor(N);
    scrubbers(R);
    C_finish(D, T#10s);
  END_STEP

  TRANSITION FROM Move_Car_17 TO START
    := C_finish;
  END_TRANSITION

END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#20ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : car_wash;
  END_RESOURCE
END_CONFIGURATION
