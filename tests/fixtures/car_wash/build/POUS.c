void LOGGER_init__(LOGGER *data__, BOOL retain) {
  __INIT_VAR(data__->EN,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->ENO,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->TRIG,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->MSG,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->LEVEL,LOGLEVEL__INFO,retain)
  __INIT_VAR(data__->TRIG0,__BOOL_LITERAL(FALSE),retain)
}

// Code part
void LOGGER_body__(LOGGER *data__) {
  // Control execution
  if (!__GET_VAR(data__->EN)) {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(FALSE));
    return;
  }
  else {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(TRUE));
  }
  // Initialise TEMP variables

  if ((__GET_VAR(data__->TRIG,) && !(__GET_VAR(data__->TRIG0,)))) {
    #define GetFbVar(var,...) __GET_VAR(data__->var,__VA_ARGS__)
    #define SetFbVar(var,val,...) __SET_VAR(data__->,var,__VA_ARGS__,val)

   LogMessage(GetFbVar(LEVEL),(char*)GetFbVar(MSG, .body),GetFbVar(MSG, .len));
  
    #undef GetFbVar
    #undef SetFbVar
;
  };
  __SET_VAR(data__->,TRIG0,,__GET_VAR(data__->TRIG,));

  goto __end;

__end:
  return;
} // LOGGER_body__() 





void CAR_WASH_init__(CAR_WASH *data__, BOOL retain) {
  __INIT_VAR(data__->AVAILABLE_LIGHT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->CONVEYOR_MOTOR,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->CONVEYOR_LIGHT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->WAX_LIGHT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->SOAP_LIGHT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->SCRUBBERS,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->SCRUB_LIGHT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->SOAP_SPRINKLER,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->WATER_SPRINKLER,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->WAX_LIQUID,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->DRYERS,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->CAR_ON_START_SENSOR,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->SERVICE_SELECTION_BUTTON,0,retain)
  __INIT_VAR(data__->WASH_ONLY_SELECTION,1,retain)
  __INIT_VAR(data__->WASH_AND_DRY_SELECTION,2,retain)
  __INIT_VAR(data__->WASH_DRY_AND_WAX_SELECTION,3,retain)
  __INIT_VAR(data__->A_RINSE2,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->A_MOVE_CAR2,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->A_SOAP0,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->A_MOVE_CAR3,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->A_SCRUB0,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->A_MOVE_CAR4,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->A_RINSE3,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->A_MOVE_CAR5,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->A_FINISH,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->B_RINSE4,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->B_MOVE_CAR6,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->B_SOAP1,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->B_MOVE_CAR7,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->B_SCRUB2,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->B_MOVE_CAR8,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->B_RINSE5,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->B_MOVE_CAR9,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->B_DRY0,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->B_MOVE_CAR10,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->B_FINISH,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_RINSE6,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_MOVE_CAR11,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_SOAP2,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_MOVE_CAR12,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_SCRUB3,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_MOVE_CAR13,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_RINSE7,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_MOVE_CAR14,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_DRY1,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_MOVE_CAR15,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_WAX_LIQUID0,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_MOVE_CAR16,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_SCRUB1,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_MOVE_CAR17,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->C_FINISH,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->_TMP_EQ14_OUT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->_TMP_EQ17_OUT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->_TMP_EQ20_OUT,__BOOL_LITERAL(FALSE),retain)
  UINT i;
  data__->__nb_steps = 37;
  static const STEP temp_step = {{0, 0}, 0, {{0, 0}, 0}};
  for(i = 0; i < data__->__nb_steps; i++) {
    data__->__step_list[i] = temp_step;
  }
  __SET_VAR(data__->,__step_list[0].X,,1);
  data__->__nb_actions = 48;
  static const ACTION temp_action = {0, {0, 0}, 0, 0, {0, 0}, {0, 0}};
  for(i = 0; i < data__->__nb_actions; i++) {
    data__->__action_list[i] = temp_action;
  }
  data__->__nb_transitions = 39;
  data__->__lasttick_time = __CURRENT_TIME;
}

// Steps definitions
#define START __step_list[0]
#define __SFC_START 0
#define SERVICE_SELECTION0 __step_list[1]
#define __SFC_SERVICE_SELECTION0 1
#define WASH_ONLY_A __step_list[2]
#define __SFC_WASH_ONLY_A 2
#define RINSE2 __step_list[3]
#define __SFC_RINSE2 3
#define MOVE_CAR2 __step_list[4]
#define __SFC_MOVE_CAR2 4
#define SOAP0 __step_list[5]
#define __SFC_SOAP0 5
#define MOVE_CAR3 __step_list[6]
#define __SFC_MOVE_CAR3 6
#define SCRUB0 __step_list[7]
#define __SFC_SCRUB0 7
#define MOVE_CAR4 __step_list[8]
#define __SFC_MOVE_CAR4 8
#define RINSE3 __step_list[9]
#define __SFC_RINSE3 9
#define MOVE_CAR_5 __step_list[10]
#define __SFC_MOVE_CAR_5 10
#define WASH_AND_DRY_B __step_list[11]
#define __SFC_WASH_AND_DRY_B 11
#define RINSE4 __step_list[12]
#define __SFC_RINSE4 12
#define MOVE_CAR6 __step_list[13]
#define __SFC_MOVE_CAR6 13
#define SOAP1 __step_list[14]
#define __SFC_SOAP1 14
#define MOVE_CAR7 __step_list[15]
#define __SFC_MOVE_CAR7 15
#define SCRUB2 __step_list[16]
#define __SFC_SCRUB2 16
#define MOVE_CAR8 __step_list[17]
#define __SFC_MOVE_CAR8 17
#define RINSE5 __step_list[18]
#define __SFC_RINSE5 18
#define MOVE_CAR9 __step_list[19]
#define __SFC_MOVE_CAR9 19
#define DRY0 __step_list[20]
#define __SFC_DRY0 20
#define MOVE_CAR10 __step_list[21]
#define __SFC_MOVE_CAR10 21
#define WASH_DRY_AND_WAX_C __step_list[22]
#define __SFC_WASH_DRY_AND_WAX_C 22
#define RINSE6 __step_list[23]
#define __SFC_RINSE6 23
#define MOVE_CAR11 __step_list[24]
#define __SFC_MOVE_CAR11 24
#define SOAP2 __step_list[25]
#define __SFC_SOAP2 25
#define MOVE_CAR12 __step_list[26]
#define __SFC_MOVE_CAR12 26
#define SCRUB3 __step_list[27]
#define __SFC_SCRUB3 27
#define MOVE_CAR13 __step_list[28]
#define __SFC_MOVE_CAR13 28
#define RINSE7 __step_list[29]
#define __SFC_RINSE7 29
#define MOVE_CAR_14 __step_list[30]
#define __SFC_MOVE_CAR_14 30
#define DRY1 __step_list[31]
#define __SFC_DRY1 31
#define MOVE_CAR_15 __step_list[32]
#define __SFC_MOVE_CAR_15 32
#define WAX_LIQUID0 __step_list[33]
#define __SFC_WAX_LIQUID0 33
#define MOVE_CAR_16 __step_list[34]
#define __SFC_MOVE_CAR_16 34
#define SCRUB1 __step_list[35]
#define __SFC_SCRUB1 35
#define MOVE_CAR_17 __step_list[36]
#define __SFC_MOVE_CAR_17 36

// Actions definitions
#define __SFC_COMPUTE_FUNCTION_BLOCKS 0
#define __SFC_AVAILABLE_LIGHT 1
#define __SFC_CONVEYOR_LIGHT 2
#define __SFC_CONVEYOR_MOTOR 3
#define __SFC_WATER_SPRINKLER 4
#define __SFC_SCRUBBERS 5
#define __SFC_WAX_LIQUID 6
#define __SFC_DRYERS 7
#define __SFC_CAR_ON_START_SENSOR 8
#define __SFC_SOAP_LIGHT 9
#define __SFC_SCRUB_LIGHT 10
#define __SFC_WAX_LIGHT 11
#define __SFC_SOAP_SPRINKLER 12
#define __SFC_A_RINSE2 13
#define __SFC_A_MOVE_CAR2 14
#define __SFC_A_SOAP0 15
#define __SFC_A_MOVE_CAR3 16
#define __SFC_A_SCRUB0 17
#define __SFC_A_MOVE_CAR4 18
#define __SFC_A_RINSE3 19
#define __SFC_A_MOVE_CAR5 20
#define __SFC_A_FINISH 21
#define __SFC_B_RINSE4 22
#define __SFC_B_MOVE_CAR6 23
#define __SFC_B_SOAP1 24
#define __SFC_B_MOVE_CAR7 25
#define __SFC_B_SCRUB2 26
#define __SFC_B_MOVE_CAR8 27
#define __SFC_B_RINSE5 28
#define __SFC_B_MOVE_CAR9 29
#define __SFC_B_DRY0 30
#define __SFC_B_MOVE_CAR10 31
#define __SFC_B_FINISH 32
#define __SFC_C_RINSE6 33
#define __SFC_C_MOVE_CAR11 34
#define __SFC_C_SOAP2 35
#define __SFC_C_MOVE_CAR12 36
#define __SFC_C_SCRUB3 37
#define __SFC_C_MOVE_CAR13 38
#define __SFC_C_RINSE7 39
#define __SFC_C_MOVE_CAR14 40
#define __SFC_C_DRY1 41
#define __SFC_C_MOVE_CAR15 42
#define __SFC_C_WAX_LIQUID0 43
#define __SFC_C_MOVE_CAR16 44
#define __SFC_C_SCRUB1 45
#define __SFC_C_MOVE_CAR17 46
#define __SFC_C_FINISH 47

// Code part
void CAR_WASH_body__(CAR_WASH *data__) {
  // Initialise TEMP variables

  INT i;
  TIME elapsed_time, current_time;

  // Calculate elapsed_time
  current_time = __CURRENT_TIME;
  elapsed_time = __time_sub(current_time, data__->__lasttick_time);
  data__->__lasttick_time = current_time;
  // Transitions initialization
  if (__DEBUG) {
    for (i = 0; i < data__->__nb_transitions; i++) {
      data__->__transition_list[i] = data__->__debug_transition_list[i];
    }
  }
  // Steps initialization
  for (i = 0; i < data__->__nb_steps; i++) {
    data__->__step_list[i].prev_state = __GET_VAR(data__->__step_list[i].X);
    if (__GET_VAR(data__->__step_list[i].X)) {
      data__->__step_list[i].T.value = __time_add(data__->__step_list[i].T.value, elapsed_time);
    }
  }
  // Actions initialization
  for (i = 0; i < data__->__nb_actions; i++) {
    __SET_VAR(data__->,__action_list[i].state,,0);
    data__->__action_list[i].set = 0;
    data__->__action_list[i].reset = 0;
    if (__time_cmp(data__->__action_list[i].set_remaining_time, __time_to_timespec(1, 0, 0, 0, 0, 0)) > 0) {
      data__->__action_list[i].set_remaining_time = __time_sub(data__->__action_list[i].set_remaining_time, elapsed_time);
      if (__time_cmp(data__->__action_list[i].set_remaining_time, __time_to_timespec(1, 0, 0, 0, 0, 0)) <= 0) {
        data__->__action_list[i].set_remaining_time = __time_to_timespec(1, 0, 0, 0, 0, 0);
        data__->__action_list[i].set = 1;
      }
    }
    if (__time_cmp(data__->__action_list[i].reset_remaining_time, __time_to_timespec(1, 0, 0, 0, 0, 0)) > 0) {
      data__->__action_list[i].reset_remaining_time = __time_sub(data__->__action_list[i].reset_remaining_time, elapsed_time);
      if (__time_cmp(data__->__action_list[i].reset_remaining_time, __time_to_timespec(1, 0, 0, 0, 0, 0)) <= 0) {
        data__->__action_list[i].reset_remaining_time = __time_to_timespec(1, 0, 0, 0, 0, 0);
        data__->__action_list[i].reset = 1;
      }
    }
  }

  // Transitions fire test
  if (__GET_VAR(data__->START.X)) {
    __SET_VAR(data__->,__transition_list[0],,__GET_VAR(data__->CAR_ON_START_SENSOR,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[0],,__GET_VAR(data__->__transition_list[0]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[0],,__GET_VAR(data__->CAR_ON_START_SENSOR,));
    }
    __SET_VAR(data__->,__transition_list[0],,0);
  }
  if (__GET_VAR(data__->SERVICE_SELECTION0.X)) {
    __SET_VAR(data__->,__transition_list[1],,__GET_VAR(data__->_TMP_EQ14_OUT,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[1],,__GET_VAR(data__->__transition_list[1]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[1],,__GET_VAR(data__->_TMP_EQ14_OUT,));
    }
    __SET_VAR(data__->,__transition_list[1],,0);
  }
  if (__GET_VAR(data__->WASH_ONLY_A.X)) {
    __SET_VAR(data__->,__transition_list[2],,__GET_VAR(data__->A_RINSE2,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[2],,__GET_VAR(data__->__transition_list[2]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[2],,__GET_VAR(data__->A_RINSE2,));
    }
    __SET_VAR(data__->,__transition_list[2],,0);
  }
  if (__GET_VAR(data__->RINSE2.X)) {
    __SET_VAR(data__->,__transition_list[3],,__GET_VAR(data__->A_MOVE_CAR2,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[3],,__GET_VAR(data__->__transition_list[3]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[3],,__GET_VAR(data__->A_MOVE_CAR2,));
    }
    __SET_VAR(data__->,__transition_list[3],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR2.X)) {
    __SET_VAR(data__->,__transition_list[4],,__GET_VAR(data__->A_SOAP0,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[4],,__GET_VAR(data__->__transition_list[4]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[4],,__GET_VAR(data__->A_SOAP0,));
    }
    __SET_VAR(data__->,__transition_list[4],,0);
  }
  if (__GET_VAR(data__->SOAP0.X)) {
    __SET_VAR(data__->,__transition_list[5],,__GET_VAR(data__->A_MOVE_CAR3,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[5],,__GET_VAR(data__->__transition_list[5]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[5],,__GET_VAR(data__->A_MOVE_CAR3,));
    }
    __SET_VAR(data__->,__transition_list[5],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR3.X)) {
    __SET_VAR(data__->,__transition_list[6],,__GET_VAR(data__->A_SCRUB0,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[6],,__GET_VAR(data__->__transition_list[6]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[6],,__GET_VAR(data__->A_SCRUB0,));
    }
    __SET_VAR(data__->,__transition_list[6],,0);
  }
  if (__GET_VAR(data__->SCRUB0.X)) {
    __SET_VAR(data__->,__transition_list[7],,__GET_VAR(data__->A_MOVE_CAR4,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[7],,__GET_VAR(data__->__transition_list[7]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[7],,__GET_VAR(data__->A_MOVE_CAR4,));
    }
    __SET_VAR(data__->,__transition_list[7],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR4.X)) {
    __SET_VAR(data__->,__transition_list[8],,__GET_VAR(data__->A_RINSE3,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[8],,__GET_VAR(data__->__transition_list[8]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[8],,__GET_VAR(data__->A_RINSE3,));
    }
    __SET_VAR(data__->,__transition_list[8],,0);
  }
  if (__GET_VAR(data__->RINSE3.X)) {
    __SET_VAR(data__->,__transition_list[9],,__GET_VAR(data__->A_MOVE_CAR5,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[9],,__GET_VAR(data__->__transition_list[9]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[9],,__GET_VAR(data__->A_MOVE_CAR5,));
    }
    __SET_VAR(data__->,__transition_list[9],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR_5.X)) {
    __SET_VAR(data__->,__transition_list[10],,__GET_VAR(data__->A_FINISH,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[10],,__GET_VAR(data__->__transition_list[10]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[10],,__GET_VAR(data__->A_FINISH,));
    }
    __SET_VAR(data__->,__transition_list[10],,0);
  }
  if (__GET_VAR(data__->SERVICE_SELECTION0.X)) {
    __SET_VAR(data__->,__transition_list[11],,__GET_VAR(data__->_TMP_EQ17_OUT,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[11],,__GET_VAR(data__->__transition_list[11]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[11],,__GET_VAR(data__->_TMP_EQ17_OUT,));
    }
    __SET_VAR(data__->,__transition_list[11],,0);
  }
  if (__GET_VAR(data__->WASH_AND_DRY_B.X)) {
    __SET_VAR(data__->,__transition_list[12],,__GET_VAR(data__->B_RINSE4,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[12],,__GET_VAR(data__->__transition_list[12]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[12],,__GET_VAR(data__->B_RINSE4,));
    }
    __SET_VAR(data__->,__transition_list[12],,0);
  }
  if (__GET_VAR(data__->RINSE4.X)) {
    __SET_VAR(data__->,__transition_list[13],,__GET_VAR(data__->B_MOVE_CAR6,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[13],,__GET_VAR(data__->__transition_list[13]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[13],,__GET_VAR(data__->B_MOVE_CAR6,));
    }
    __SET_VAR(data__->,__transition_list[13],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR6.X)) {
    __SET_VAR(data__->,__transition_list[14],,__GET_VAR(data__->B_SOAP1,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[14],,__GET_VAR(data__->__transition_list[14]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[14],,__GET_VAR(data__->B_SOAP1,));
    }
    __SET_VAR(data__->,__transition_list[14],,0);
  }
  if (__GET_VAR(data__->SOAP1.X)) {
    __SET_VAR(data__->,__transition_list[15],,__GET_VAR(data__->B_MOVE_CAR7,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[15],,__GET_VAR(data__->__transition_list[15]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[15],,__GET_VAR(data__->B_MOVE_CAR7,));
    }
    __SET_VAR(data__->,__transition_list[15],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR7.X)) {
    __SET_VAR(data__->,__transition_list[16],,__GET_VAR(data__->B_SCRUB2,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[16],,__GET_VAR(data__->__transition_list[16]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[16],,__GET_VAR(data__->B_SCRUB2,));
    }
    __SET_VAR(data__->,__transition_list[16],,0);
  }
  if (__GET_VAR(data__->SCRUB2.X)) {
    __SET_VAR(data__->,__transition_list[17],,__GET_VAR(data__->B_MOVE_CAR8,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[17],,__GET_VAR(data__->__transition_list[17]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[17],,__GET_VAR(data__->B_MOVE_CAR8,));
    }
    __SET_VAR(data__->,__transition_list[17],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR8.X)) {
    __SET_VAR(data__->,__transition_list[18],,__GET_VAR(data__->B_RINSE5,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[18],,__GET_VAR(data__->__transition_list[18]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[18],,__GET_VAR(data__->B_RINSE5,));
    }
    __SET_VAR(data__->,__transition_list[18],,0);
  }
  if (__GET_VAR(data__->RINSE5.X)) {
    __SET_VAR(data__->,__transition_list[19],,__GET_VAR(data__->B_MOVE_CAR9,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[19],,__GET_VAR(data__->__transition_list[19]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[19],,__GET_VAR(data__->B_MOVE_CAR9,));
    }
    __SET_VAR(data__->,__transition_list[19],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR9.X)) {
    __SET_VAR(data__->,__transition_list[20],,__GET_VAR(data__->B_DRY0,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[20],,__GET_VAR(data__->__transition_list[20]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[20],,__GET_VAR(data__->B_DRY0,));
    }
    __SET_VAR(data__->,__transition_list[20],,0);
  }
  if (__GET_VAR(data__->DRY0.X)) {
    __SET_VAR(data__->,__transition_list[21],,__GET_VAR(data__->B_MOVE_CAR10,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[21],,__GET_VAR(data__->__transition_list[21]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[21],,__GET_VAR(data__->B_MOVE_CAR10,));
    }
    __SET_VAR(data__->,__transition_list[21],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR10.X)) {
    __SET_VAR(data__->,__transition_list[22],,__GET_VAR(data__->B_FINISH,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[22],,__GET_VAR(data__->__transition_list[22]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[22],,__GET_VAR(data__->B_FINISH,));
    }
    __SET_VAR(data__->,__transition_list[22],,0);
  }
  if (__GET_VAR(data__->SERVICE_SELECTION0.X)) {
    __SET_VAR(data__->,__transition_list[23],,__GET_VAR(data__->_TMP_EQ20_OUT,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[23],,__GET_VAR(data__->__transition_list[23]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[23],,__GET_VAR(data__->_TMP_EQ20_OUT,));
    }
    __SET_VAR(data__->,__transition_list[23],,0);
  }
  if (__GET_VAR(data__->WASH_DRY_AND_WAX_C.X)) {
    __SET_VAR(data__->,__transition_list[24],,__GET_VAR(data__->C_RINSE6,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[24],,__GET_VAR(data__->__transition_list[24]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[24],,__GET_VAR(data__->C_RINSE6,));
    }
    __SET_VAR(data__->,__transition_list[24],,0);
  }
  if (__GET_VAR(data__->RINSE6.X)) {
    __SET_VAR(data__->,__transition_list[25],,__GET_VAR(data__->C_MOVE_CAR11,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[25],,__GET_VAR(data__->__transition_list[25]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[25],,__GET_VAR(data__->C_MOVE_CAR11,));
    }
    __SET_VAR(data__->,__transition_list[25],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR11.X)) {
    __SET_VAR(data__->,__transition_list[26],,__GET_VAR(data__->C_SOAP2,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[26],,__GET_VAR(data__->__transition_list[26]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[26],,__GET_VAR(data__->C_SOAP2,));
    }
    __SET_VAR(data__->,__transition_list[26],,0);
  }
  if (__GET_VAR(data__->SOAP2.X)) {
    __SET_VAR(data__->,__transition_list[27],,__GET_VAR(data__->C_MOVE_CAR12,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[27],,__GET_VAR(data__->__transition_list[27]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[27],,__GET_VAR(data__->C_MOVE_CAR12,));
    }
    __SET_VAR(data__->,__transition_list[27],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR12.X)) {
    __SET_VAR(data__->,__transition_list[28],,__GET_VAR(data__->C_SCRUB3,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[28],,__GET_VAR(data__->__transition_list[28]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[28],,__GET_VAR(data__->C_SCRUB3,));
    }
    __SET_VAR(data__->,__transition_list[28],,0);
  }
  if (__GET_VAR(data__->SCRUB3.X)) {
    __SET_VAR(data__->,__transition_list[29],,__GET_VAR(data__->C_MOVE_CAR13,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[29],,__GET_VAR(data__->__transition_list[29]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[29],,__GET_VAR(data__->C_MOVE_CAR13,));
    }
    __SET_VAR(data__->,__transition_list[29],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR13.X)) {
    __SET_VAR(data__->,__transition_list[30],,__GET_VAR(data__->C_RINSE7,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[30],,__GET_VAR(data__->__transition_list[30]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[30],,__GET_VAR(data__->C_RINSE7,));
    }
    __SET_VAR(data__->,__transition_list[30],,0);
  }
  if (__GET_VAR(data__->RINSE7.X)) {
    __SET_VAR(data__->,__transition_list[31],,__GET_VAR(data__->C_MOVE_CAR14,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[31],,__GET_VAR(data__->__transition_list[31]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[31],,__GET_VAR(data__->C_MOVE_CAR14,));
    }
    __SET_VAR(data__->,__transition_list[31],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR_14.X)) {
    __SET_VAR(data__->,__transition_list[32],,__GET_VAR(data__->C_DRY1,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[32],,__GET_VAR(data__->__transition_list[32]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[32],,__GET_VAR(data__->C_DRY1,));
    }
    __SET_VAR(data__->,__transition_list[32],,0);
  }
  if (__GET_VAR(data__->DRY1.X)) {
    __SET_VAR(data__->,__transition_list[33],,__GET_VAR(data__->C_MOVE_CAR15,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[33],,__GET_VAR(data__->__transition_list[33]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[33],,__GET_VAR(data__->C_MOVE_CAR15,));
    }
    __SET_VAR(data__->,__transition_list[33],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR_15.X)) {
    __SET_VAR(data__->,__transition_list[34],,__GET_VAR(data__->C_WAX_LIQUID0,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[34],,__GET_VAR(data__->__transition_list[34]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[34],,__GET_VAR(data__->C_WAX_LIQUID0,));
    }
    __SET_VAR(data__->,__transition_list[34],,0);
  }
  if (__GET_VAR(data__->WAX_LIQUID0.X)) {
    __SET_VAR(data__->,__transition_list[35],,__GET_VAR(data__->C_MOVE_CAR16,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[35],,__GET_VAR(data__->__transition_list[35]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[35],,__GET_VAR(data__->C_MOVE_CAR16,));
    }
    __SET_VAR(data__->,__transition_list[35],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR_16.X)) {
    __SET_VAR(data__->,__transition_list[36],,__GET_VAR(data__->C_SCRUB1,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[36],,__GET_VAR(data__->__transition_list[36]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[36],,__GET_VAR(data__->C_SCRUB1,));
    }
    __SET_VAR(data__->,__transition_list[36],,0);
  }
  if (__GET_VAR(data__->SCRUB1.X)) {
    __SET_VAR(data__->,__transition_list[37],,__GET_VAR(data__->C_MOVE_CAR17,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[37],,__GET_VAR(data__->__transition_list[37]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[37],,__GET_VAR(data__->C_MOVE_CAR17,));
    }
    __SET_VAR(data__->,__transition_list[37],,0);
  }
  if (__GET_VAR(data__->MOVE_CAR_17.X)) {
    __SET_VAR(data__->,__transition_list[38],,__GET_VAR(data__->C_FINISH,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[38],,__GET_VAR(data__->__transition_list[38]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[38],,__GET_VAR(data__->C_FINISH,));
    }
    __SET_VAR(data__->,__transition_list[38],,0);
  }

  // Transitions reset steps
  if (__GET_VAR(data__->__transition_list[0])) {
    __SET_VAR(data__->,START.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[1])) {
    __SET_VAR(data__->,SERVICE_SELECTION0.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[2])) {
    __SET_VAR(data__->,WASH_ONLY_A.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[3])) {
    __SET_VAR(data__->,RINSE2.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[4])) {
    __SET_VAR(data__->,MOVE_CAR2.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[5])) {
    __SET_VAR(data__->,SOAP0.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[6])) {
    __SET_VAR(data__->,MOVE_CAR3.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[7])) {
    __SET_VAR(data__->,SCRUB0.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[8])) {
    __SET_VAR(data__->,MOVE_CAR4.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[9])) {
    __SET_VAR(data__->,RINSE3.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[10])) {
    __SET_VAR(data__->,MOVE_CAR_5.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[11])) {
    __SET_VAR(data__->,SERVICE_SELECTION0.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[12])) {
    __SET_VAR(data__->,WASH_AND_DRY_B.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[13])) {
    __SET_VAR(data__->,RINSE4.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[14])) {
    __SET_VAR(data__->,MOVE_CAR6.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[15])) {
    __SET_VAR(data__->,SOAP1.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[16])) {
    __SET_VAR(data__->,MOVE_CAR7.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[17])) {
    __SET_VAR(data__->,SCRUB2.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[18])) {
    __SET_VAR(data__->,MOVE_CAR8.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[19])) {
    __SET_VAR(data__->,RINSE5.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[20])) {
    __SET_VAR(data__->,MOVE_CAR9.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[21])) {
    __SET_VAR(data__->,DRY0.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[22])) {
    __SET_VAR(data__->,MOVE_CAR10.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[23])) {
    __SET_VAR(data__->,SERVICE_SELECTION0.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[24])) {
    __SET_VAR(data__->,WASH_DRY_AND_WAX_C.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[25])) {
    __SET_VAR(data__->,RINSE6.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[26])) {
    __SET_VAR(data__->,MOVE_CAR11.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[27])) {
    __SET_VAR(data__->,SOAP2.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[28])) {
    __SET_VAR(data__->,MOVE_CAR12.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[29])) {
    __SET_VAR(data__->,SCRUB3.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[30])) {
    __SET_VAR(data__->,MOVE_CAR13.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[31])) {
    __SET_VAR(data__->,RINSE7.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[32])) {
    __SET_VAR(data__->,MOVE_CAR_14.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[33])) {
    __SET_VAR(data__->,DRY1.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[34])) {
    __SET_VAR(data__->,MOVE_CAR_15.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[35])) {
    __SET_VAR(data__->,WAX_LIQUID0.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[36])) {
    __SET_VAR(data__->,MOVE_CAR_16.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[37])) {
    __SET_VAR(data__->,SCRUB1.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[38])) {
    __SET_VAR(data__->,MOVE_CAR_17.X,,0);
  }

  // Transitions set steps
  if (__GET_VAR(data__->__transition_list[0])) {
    __SET_VAR(data__->,SERVICE_SELECTION0.X,,1);
    data__->SERVICE_SELECTION0.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[1])) {
    __SET_VAR(data__->,WASH_ONLY_A.X,,1);
    data__->WASH_ONLY_A.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[2])) {
    __SET_VAR(data__->,RINSE2.X,,1);
    data__->RINSE2.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[3])) {
    __SET_VAR(data__->,MOVE_CAR2.X,,1);
    data__->MOVE_CAR2.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[4])) {
    __SET_VAR(data__->,SOAP0.X,,1);
    data__->SOAP0.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[5])) {
    __SET_VAR(data__->,MOVE_CAR3.X,,1);
    data__->MOVE_CAR3.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[6])) {
    __SET_VAR(data__->,SCRUB0.X,,1);
    data__->SCRUB0.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[7])) {
    __SET_VAR(data__->,MOVE_CAR4.X,,1);
    data__->MOVE_CAR4.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[8])) {
    __SET_VAR(data__->,RINSE3.X,,1);
    data__->RINSE3.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[9])) {
    __SET_VAR(data__->,MOVE_CAR_5.X,,1);
    data__->MOVE_CAR_5.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[10])) {
    __SET_VAR(data__->,START.X,,1);
    data__->START.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[11])) {
    __SET_VAR(data__->,WASH_AND_DRY_B.X,,1);
    data__->WASH_AND_DRY_B.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[12])) {
    __SET_VAR(data__->,RINSE4.X,,1);
    data__->RINSE4.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[13])) {
    __SET_VAR(data__->,MOVE_CAR6.X,,1);
    data__->MOVE_CAR6.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[14])) {
    __SET_VAR(data__->,SOAP1.X,,1);
    data__->SOAP1.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[15])) {
    __SET_VAR(data__->,MOVE_CAR7.X,,1);
    data__->MOVE_CAR7.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[16])) {
    __SET_VAR(data__->,SCRUB2.X,,1);
    data__->SCRUB2.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[17])) {
    __SET_VAR(data__->,MOVE_CAR8.X,,1);
    data__->MOVE_CAR8.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[18])) {
    __SET_VAR(data__->,RINSE5.X,,1);
    data__->RINSE5.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[19])) {
    __SET_VAR(data__->,MOVE_CAR9.X,,1);
    data__->MOVE_CAR9.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[20])) {
    __SET_VAR(data__->,DRY0.X,,1);
    data__->DRY0.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[21])) {
    __SET_VAR(data__->,MOVE_CAR10.X,,1);
    data__->MOVE_CAR10.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[22])) {
    __SET_VAR(data__->,START.X,,1);
    data__->START.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[23])) {
    __SET_VAR(data__->,WASH_DRY_AND_WAX_C.X,,1);
    data__->WASH_DRY_AND_WAX_C.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[24])) {
    __SET_VAR(data__->,RINSE6.X,,1);
    data__->RINSE6.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[25])) {
    __SET_VAR(data__->,MOVE_CAR11.X,,1);
    data__->MOVE_CAR11.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[26])) {
    __SET_VAR(data__->,SOAP2.X,,1);
    data__->SOAP2.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[27])) {
    __SET_VAR(data__->,MOVE_CAR12.X,,1);
    data__->MOVE_CAR12.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[28])) {
    __SET_VAR(data__->,SCRUB3.X,,1);
    data__->SCRUB3.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[29])) {
    __SET_VAR(data__->,MOVE_CAR13.X,,1);
    data__->MOVE_CAR13.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[30])) {
    __SET_VAR(data__->,RINSE7.X,,1);
    data__->RINSE7.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[31])) {
    __SET_VAR(data__->,MOVE_CAR_14.X,,1);
    data__->MOVE_CAR_14.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[32])) {
    __SET_VAR(data__->,DRY1.X,,1);
    data__->DRY1.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[33])) {
    __SET_VAR(data__->,MOVE_CAR_15.X,,1);
    data__->MOVE_CAR_15.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[34])) {
    __SET_VAR(data__->,WAX_LIQUID0.X,,1);
    data__->WAX_LIQUID0.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[35])) {
    __SET_VAR(data__->,MOVE_CAR_16.X,,1);
    data__->MOVE_CAR_16.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[36])) {
    __SET_VAR(data__->,SCRUB1.X,,1);
    data__->SCRUB1.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[37])) {
    __SET_VAR(data__->,MOVE_CAR_17.X,,1);
    data__->MOVE_CAR_17.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[38])) {
    __SET_VAR(data__->,START.X,,1);
    data__->START.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }

  // Steps association
  // START action associations
  {
    char active = __GET_VAR(data__->START.X);
    char activated = active && !data__->START.prev_state;
    char desactivated = !active && data__->START.prev_state;

    if (active)       {data__->__action_list[__SFC_AVAILABLE_LIGHT].set = 1;}

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active)       {data__->__action_list[__SFC_WATER_SPRINKLER].reset = 1;}

    if (active)       {data__->__action_list[__SFC_SCRUBBERS].reset = 1;}

    if (active)       {data__->__action_list[__SFC_WAX_LIQUID].reset = 1;}

    if (active)       {data__->__action_list[__SFC_DRYERS].reset = 1;}

    if (active)       {data__->__action_list[__SFC_CAR_ON_START_SENSOR].reset = 1;}

    if (active)       {data__->__action_list[__SFC_SOAP_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_SCRUB_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_WAX_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_SOAP_SPRINKLER].reset = 1;}

    if (active)       {data__->__action_list[__SFC_COMPUTE_FUNCTION_BLOCKS].set = 1;}

  }

  // SERVICE_SELECTION0 action associations
  {
    char active = __GET_VAR(data__->SERVICE_SELECTION0.X);
    char activated = active && !data__->SERVICE_SELECTION0.prev_state;
    char desactivated = !active && data__->SERVICE_SELECTION0.prev_state;

    if (active)       {data__->__action_list[__SFC_AVAILABLE_LIGHT].reset = 1;}

  }

  // WASH_ONLY_A action associations
  {
    char active = __GET_VAR(data__->WASH_ONLY_A.X);
    char activated = active && !data__->WASH_ONLY_A.prev_state;
    char desactivated = !active && data__->WASH_ONLY_A.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active && __time_cmp(data__->WASH_ONLY_A.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,A_RINSE2,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,A_RINSE2,,0);};

  }

  // RINSE2 action associations
  {
    char active = __GET_VAR(data__->RINSE2.X);
    char activated = active && !data__->RINSE2.prev_state;
    char desactivated = !active && data__->RINSE2.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {__SET_VAR(data__->,WATER_SPRINKLER,,1);};
    if (desactivated) {__SET_VAR(data__->,WATER_SPRINKLER,,0);};

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active && __time_cmp(data__->RINSE2.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,A_MOVE_CAR2,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,A_MOVE_CAR2,,0);};

  }

  // MOVE_CAR2 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR2.X);
    char activated = active && !data__->MOVE_CAR2.prev_state;
    char desactivated = !active && data__->MOVE_CAR2.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_WATER_SPRINKLER].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR2.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,A_SOAP0,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,A_SOAP0,,0);};

  }

  // SOAP0 action associations
  {
    char active = __GET_VAR(data__->SOAP0.X);
    char activated = active && !data__->SOAP0.prev_state;
    char desactivated = !active && data__->SOAP0.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {__SET_VAR(data__->,SOAP_SPRINKLER,,1);};
    if (desactivated) {__SET_VAR(data__->,SOAP_SPRINKLER,,0);};

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active && __time_cmp(data__->SOAP0.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,A_MOVE_CAR3,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,A_MOVE_CAR3,,0);};

  }

  // MOVE_CAR3 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR3.X);
    char activated = active && !data__->MOVE_CAR3.prev_state;
    char desactivated = !active && data__->MOVE_CAR3.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_SOAP_SPRINKLER].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR3.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,A_SCRUB0,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,A_SCRUB0,,0);};

  }

  // SCRUB0 action associations
  {
    char active = __GET_VAR(data__->SCRUB0.X);
    char activated = active && !data__->SCRUB0.prev_state;
    char desactivated = !active && data__->SCRUB0.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active)       {__SET_VAR(data__->,SCRUBBERS,,1);};
    if (desactivated) {__SET_VAR(data__->,SCRUBBERS,,0);};

    if (active && __time_cmp(data__->SCRUB0.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,A_MOVE_CAR4,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,A_MOVE_CAR4,,0);};

  }

  // MOVE_CAR4 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR4.X);
    char activated = active && !data__->MOVE_CAR4.prev_state;
    char desactivated = !active && data__->MOVE_CAR4.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_SOAP_SPRINKLER].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR4.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,A_RINSE3,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,A_RINSE3,,0);};

  }

  // RINSE3 action associations
  {
    char active = __GET_VAR(data__->RINSE3.X);
    char activated = active && !data__->RINSE3.prev_state;
    char desactivated = !active && data__->RINSE3.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active)       {__SET_VAR(data__->,WATER_SPRINKLER,,1);};
    if (desactivated) {__SET_VAR(data__->,WATER_SPRINKLER,,0);};

    if (active && __time_cmp(data__->RINSE3.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,A_MOVE_CAR5,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,A_MOVE_CAR5,,0);};

  }

  // MOVE_CAR_5 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR_5.X);
    char activated = active && !data__->MOVE_CAR_5.prev_state;
    char desactivated = !active && data__->MOVE_CAR_5.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_SOAP_SPRINKLER].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR_5.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,A_FINISH,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,A_FINISH,,0);};

  }

  // WASH_AND_DRY_B action associations
  {
    char active = __GET_VAR(data__->WASH_AND_DRY_B.X);
    char activated = active && !data__->WASH_AND_DRY_B.prev_state;
    char desactivated = !active && data__->WASH_AND_DRY_B.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active && __time_cmp(data__->WASH_AND_DRY_B.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,B_RINSE4,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,B_RINSE4,,0);};

  }

  // RINSE4 action associations
  {
    char active = __GET_VAR(data__->RINSE4.X);
    char activated = active && !data__->RINSE4.prev_state;
    char desactivated = !active && data__->RINSE4.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {__SET_VAR(data__->,WATER_SPRINKLER,,1);};
    if (desactivated) {__SET_VAR(data__->,WATER_SPRINKLER,,0);};

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active && __time_cmp(data__->RINSE4.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,B_MOVE_CAR6,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,B_MOVE_CAR6,,0);};

  }

  // MOVE_CAR6 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR6.X);
    char activated = active && !data__->MOVE_CAR6.prev_state;
    char desactivated = !active && data__->MOVE_CAR6.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_WATER_SPRINKLER].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR6.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,B_SOAP1,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,B_SOAP1,,0);};

  }

  // SOAP1 action associations
  {
    char active = __GET_VAR(data__->SOAP1.X);
    char activated = active && !data__->SOAP1.prev_state;
    char desactivated = !active && data__->SOAP1.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {__SET_VAR(data__->,SOAP_SPRINKLER,,1);};
    if (desactivated) {__SET_VAR(data__->,SOAP_SPRINKLER,,0);};

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active && __time_cmp(data__->SOAP1.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,B_MOVE_CAR7,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,B_MOVE_CAR7,,0);};

  }

  // MOVE_CAR7 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR7.X);
    char activated = active && !data__->MOVE_CAR7.prev_state;
    char desactivated = !active && data__->MOVE_CAR7.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_SOAP_SPRINKLER].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR7.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,B_SCRUB2,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,B_SCRUB2,,0);};

  }

  // SCRUB2 action associations
  {
    char active = __GET_VAR(data__->SCRUB2.X);
    char activated = active && !data__->SCRUB2.prev_state;
    char desactivated = !active && data__->SCRUB2.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active)       {__SET_VAR(data__->,SCRUBBERS,,1);};
    if (desactivated) {__SET_VAR(data__->,SCRUBBERS,,0);};

    if (active && __time_cmp(data__->SCRUB2.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,B_MOVE_CAR8,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,B_MOVE_CAR8,,0);};

  }

  // MOVE_CAR8 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR8.X);
    char activated = active && !data__->MOVE_CAR8.prev_state;
    char desactivated = !active && data__->MOVE_CAR8.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_SOAP_SPRINKLER].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR8.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,B_RINSE5,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,B_RINSE5,,0);};

  }

  // RINSE5 action associations
  {
    char active = __GET_VAR(data__->RINSE5.X);
    char activated = active && !data__->RINSE5.prev_state;
    char desactivated = !active && data__->RINSE5.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active)       {__SET_VAR(data__->,WATER_SPRINKLER,,1);};
    if (desactivated) {__SET_VAR(data__->,WATER_SPRINKLER,,0);};

    if (active && __time_cmp(data__->RINSE5.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,B_MOVE_CAR9,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,B_MOVE_CAR9,,0);};

  }

  // MOVE_CAR9 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR9.X);
    char activated = active && !data__->MOVE_CAR9.prev_state;
    char desactivated = !active && data__->MOVE_CAR9.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_SOAP_SPRINKLER].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR9.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,B_DRY0,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,B_DRY0,,0);};

  }

  // DRY0 action associations
  {
    char active = __GET_VAR(data__->DRY0.X);
    char activated = active && !data__->DRY0.prev_state;
    char desactivated = !active && data__->DRY0.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active)       {__SET_VAR(data__->,DRYERS,,1);};
    if (desactivated) {__SET_VAR(data__->,DRYERS,,0);};

    if (active && __time_cmp(data__->DRY0.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,B_MOVE_CAR10,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,B_MOVE_CAR10,,0);};

  }

  // MOVE_CAR10 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR10.X);
    char activated = active && !data__->MOVE_CAR10.prev_state;
    char desactivated = !active && data__->MOVE_CAR10.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_DRYERS].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR10.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,B_FINISH,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,B_FINISH,,0);};

  }

  // WASH_DRY_AND_WAX_C action associations
  {
    char active = __GET_VAR(data__->WASH_DRY_AND_WAX_C.X);
    char activated = active && !data__->WASH_DRY_AND_WAX_C.prev_state;
    char desactivated = !active && data__->WASH_DRY_AND_WAX_C.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active && __time_cmp(data__->WASH_DRY_AND_WAX_C.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_RINSE6,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_RINSE6,,0);};

  }

  // RINSE6 action associations
  {
    char active = __GET_VAR(data__->RINSE6.X);
    char activated = active && !data__->RINSE6.prev_state;
    char desactivated = !active && data__->RINSE6.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {__SET_VAR(data__->,WATER_SPRINKLER,,1);};
    if (desactivated) {__SET_VAR(data__->,WATER_SPRINKLER,,0);};

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active && __time_cmp(data__->RINSE6.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_MOVE_CAR11,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_MOVE_CAR11,,0);};

  }

  // MOVE_CAR11 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR11.X);
    char activated = active && !data__->MOVE_CAR11.prev_state;
    char desactivated = !active && data__->MOVE_CAR11.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_WATER_SPRINKLER].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR11.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_SOAP2,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_SOAP2,,0);};

  }

  // SOAP2 action associations
  {
    char active = __GET_VAR(data__->SOAP2.X);
    char activated = active && !data__->SOAP2.prev_state;
    char desactivated = !active && data__->SOAP2.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {__SET_VAR(data__->,SOAP_SPRINKLER,,1);};
    if (desactivated) {__SET_VAR(data__->,SOAP_SPRINKLER,,0);};

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active && __time_cmp(data__->SOAP2.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_MOVE_CAR12,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_MOVE_CAR12,,0);};

  }

  // MOVE_CAR12 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR12.X);
    char activated = active && !data__->MOVE_CAR12.prev_state;
    char desactivated = !active && data__->MOVE_CAR12.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_SOAP_SPRINKLER].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR12.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_SCRUB3,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_SCRUB3,,0);};

  }

  // SCRUB3 action associations
  {
    char active = __GET_VAR(data__->SCRUB3.X);
    char activated = active && !data__->SCRUB3.prev_state;
    char desactivated = !active && data__->SCRUB3.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active)       {__SET_VAR(data__->,SCRUBBERS,,1);};
    if (desactivated) {__SET_VAR(data__->,SCRUBBERS,,0);};

    if (active && __time_cmp(data__->SCRUB3.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_MOVE_CAR13,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_MOVE_CAR13,,0);};

  }

  // MOVE_CAR13 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR13.X);
    char activated = active && !data__->MOVE_CAR13.prev_state;
    char desactivated = !active && data__->MOVE_CAR13.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_SOAP_SPRINKLER].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR13.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_RINSE7,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_RINSE7,,0);};

  }

  // RINSE7 action associations
  {
    char active = __GET_VAR(data__->RINSE7.X);
    char activated = active && !data__->RINSE7.prev_state;
    char desactivated = !active && data__->RINSE7.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active)       {__SET_VAR(data__->,WATER_SPRINKLER,,1);};
    if (desactivated) {__SET_VAR(data__->,WATER_SPRINKLER,,0);};

    if (active && __time_cmp(data__->RINSE7.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_MOVE_CAR14,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_MOVE_CAR14,,0);};

  }

  // MOVE_CAR_14 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR_14.X);
    char activated = active && !data__->MOVE_CAR_14.prev_state;
    char desactivated = !active && data__->MOVE_CAR_14.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_SOAP_SPRINKLER].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR_14.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_DRY1,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_DRY1,,0);};

  }

  // DRY1 action associations
  {
    char active = __GET_VAR(data__->DRY1.X);
    char activated = active && !data__->DRY1.prev_state;
    char desactivated = !active && data__->DRY1.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active)       {__SET_VAR(data__->,DRYERS,,1);};
    if (desactivated) {__SET_VAR(data__->,DRYERS,,0);};

    if (active && __time_cmp(data__->DRY1.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_MOVE_CAR15,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_MOVE_CAR15,,0);};

  }

  // MOVE_CAR_15 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR_15.X);
    char activated = active && !data__->MOVE_CAR_15.prev_state;
    char desactivated = !active && data__->MOVE_CAR_15.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_DRYERS].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR_15.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_WAX_LIQUID0,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_WAX_LIQUID0,,0);};

  }

  // WAX_LIQUID0 action associations
  {
    char active = __GET_VAR(data__->WAX_LIQUID0.X);
    char activated = active && !data__->WAX_LIQUID0.prev_state;
    char desactivated = !active && data__->WAX_LIQUID0.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active)       {__SET_VAR(data__->,WAX_LIQUID,,1);};
    if (desactivated) {__SET_VAR(data__->,WAX_LIQUID,,0);};

    if (active && __time_cmp(data__->WAX_LIQUID0.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_MOVE_CAR16,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_MOVE_CAR16,,0);};

  }

  // MOVE_CAR_16 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR_16.X);
    char activated = active && !data__->MOVE_CAR_16.prev_state;
    char desactivated = !active && data__->MOVE_CAR_16.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_WAX_LIQUID].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR_16.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_SCRUB1,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_SCRUB1,,0);};

  }

  // SCRUB1 action associations
  {
    char active = __GET_VAR(data__->SCRUB1.X);
    char activated = active && !data__->SCRUB1.prev_state;
    char desactivated = !active && data__->SCRUB1.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active)       {__SET_VAR(data__->,SCRUBBERS,,1);};
    if (desactivated) {__SET_VAR(data__->,SCRUBBERS,,0);};

    if (active && __time_cmp(data__->SCRUB1.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_MOVE_CAR17,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_MOVE_CAR17,,0);};

  }

  // MOVE_CAR_17 action associations
  {
    char active = __GET_VAR(data__->MOVE_CAR_17.X);
    char activated = active && !data__->MOVE_CAR_17.prev_state;
    char desactivated = !active && data__->MOVE_CAR_17.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_LIGHT,,0);};

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_SCRUBBERS].reset = 1;}

    if (active && __time_cmp(data__->MOVE_CAR_17.T.value, __time_to_timespec(1, 0, 10, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,C_FINISH,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,C_FINISH,,0);};

  }


  // Actions state evaluation
  for (i = 0; i < data__->__nb_actions; i++) {
    if (data__->__action_list[i].set) {
      data__->__action_list[i].set_remaining_time = __time_to_timespec(1, 0, 0, 0, 0, 0);
      data__->__action_list[i].stored = 1;
    }
    if (data__->__action_list[i].reset) {
      data__->__action_list[i].reset_remaining_time = __time_to_timespec(1, 0, 0, 0, 0, 0);
      data__->__action_list[i].stored = 0;
    }
    __SET_VAR(data__->,__action_list[i].state,,__GET_VAR(data__->__action_list[i].state) | data__->__action_list[i].stored);
  }

  // Actions execution
  if (data__->__action_list[__SFC_AVAILABLE_LIGHT].reset) {
    __SET_VAR(data__->,AVAILABLE_LIGHT,,0);
  }
  else if (data__->__action_list[__SFC_AVAILABLE_LIGHT].set) {
    __SET_VAR(data__->,AVAILABLE_LIGHT,,1);
  }
  if (data__->__action_list[__SFC_CONVEYOR_LIGHT].reset) {
    __SET_VAR(data__->,CONVEYOR_LIGHT,,0);
  }
  else if (data__->__action_list[__SFC_CONVEYOR_LIGHT].set) {
    __SET_VAR(data__->,CONVEYOR_LIGHT,,1);
  }
  if (data__->__action_list[__SFC_CONVEYOR_MOTOR].reset) {
    __SET_VAR(data__->,CONVEYOR_MOTOR,,0);
  }
  else if (data__->__action_list[__SFC_CONVEYOR_MOTOR].set) {
    __SET_VAR(data__->,CONVEYOR_MOTOR,,1);
  }
  if (data__->__action_list[__SFC_WATER_SPRINKLER].reset) {
    __SET_VAR(data__->,WATER_SPRINKLER,,0);
  }
  else if (data__->__action_list[__SFC_WATER_SPRINKLER].set) {
    __SET_VAR(data__->,WATER_SPRINKLER,,1);
  }
  if (data__->__action_list[__SFC_SCRUBBERS].reset) {
    __SET_VAR(data__->,SCRUBBERS,,0);
  }
  else if (data__->__action_list[__SFC_SCRUBBERS].set) {
    __SET_VAR(data__->,SCRUBBERS,,1);
  }
  if (data__->__action_list[__SFC_WAX_LIQUID].reset) {
    __SET_VAR(data__->,WAX_LIQUID,,0);
  }
  else if (data__->__action_list[__SFC_WAX_LIQUID].set) {
    __SET_VAR(data__->,WAX_LIQUID,,1);
  }
  if (data__->__action_list[__SFC_DRYERS].reset) {
    __SET_VAR(data__->,DRYERS,,0);
  }
  else if (data__->__action_list[__SFC_DRYERS].set) {
    __SET_VAR(data__->,DRYERS,,1);
  }
  if (data__->__action_list[__SFC_CAR_ON_START_SENSOR].reset) {
    __SET_VAR(data__->,CAR_ON_START_SENSOR,,0);
  }
  else if (data__->__action_list[__SFC_CAR_ON_START_SENSOR].set) {
    __SET_VAR(data__->,CAR_ON_START_SENSOR,,1);
  }
  if (data__->__action_list[__SFC_SOAP_LIGHT].reset) {
    __SET_VAR(data__->,SOAP_LIGHT,,0);
  }
  else if (data__->__action_list[__SFC_SOAP_LIGHT].set) {
    __SET_VAR(data__->,SOAP_LIGHT,,1);
  }
  if (data__->__action_list[__SFC_SCRUB_LIGHT].reset) {
    __SET_VAR(data__->,SCRUB_LIGHT,,0);
  }
  else if (data__->__action_list[__SFC_SCRUB_LIGHT].set) {
    __SET_VAR(data__->,SCRUB_LIGHT,,1);
  }
  if (data__->__action_list[__SFC_WAX_LIGHT].reset) {
    __SET_VAR(data__->,WAX_LIGHT,,0);
  }
  else if (data__->__action_list[__SFC_WAX_LIGHT].set) {
    __SET_VAR(data__->,WAX_LIGHT,,1);
  }
  if (data__->__action_list[__SFC_SOAP_SPRINKLER].reset) {
    __SET_VAR(data__->,SOAP_SPRINKLER,,0);
  }
  else if (data__->__action_list[__SFC_SOAP_SPRINKLER].set) {
    __SET_VAR(data__->,SOAP_SPRINKLER,,1);
  }
  if (data__->__action_list[__SFC_A_RINSE2].reset) {
    __SET_VAR(data__->,A_RINSE2,,0);
  }
  else if (data__->__action_list[__SFC_A_RINSE2].set) {
    __SET_VAR(data__->,A_RINSE2,,1);
  }
  if (data__->__action_list[__SFC_A_MOVE_CAR2].reset) {
    __SET_VAR(data__->,A_MOVE_CAR2,,0);
  }
  else if (data__->__action_list[__SFC_A_MOVE_CAR2].set) {
    __SET_VAR(data__->,A_MOVE_CAR2,,1);
  }
  if (data__->__action_list[__SFC_A_SOAP0].reset) {
    __SET_VAR(data__->,A_SOAP0,,0);
  }
  else if (data__->__action_list[__SFC_A_SOAP0].set) {
    __SET_VAR(data__->,A_SOAP0,,1);
  }
  if (data__->__action_list[__SFC_A_MOVE_CAR3].reset) {
    __SET_VAR(data__->,A_MOVE_CAR3,,0);
  }
  else if (data__->__action_list[__SFC_A_MOVE_CAR3].set) {
    __SET_VAR(data__->,A_MOVE_CAR3,,1);
  }
  if (data__->__action_list[__SFC_A_SCRUB0].reset) {
    __SET_VAR(data__->,A_SCRUB0,,0);
  }
  else if (data__->__action_list[__SFC_A_SCRUB0].set) {
    __SET_VAR(data__->,A_SCRUB0,,1);
  }
  if (data__->__action_list[__SFC_A_MOVE_CAR4].reset) {
    __SET_VAR(data__->,A_MOVE_CAR4,,0);
  }
  else if (data__->__action_list[__SFC_A_MOVE_CAR4].set) {
    __SET_VAR(data__->,A_MOVE_CAR4,,1);
  }
  if (data__->__action_list[__SFC_A_RINSE3].reset) {
    __SET_VAR(data__->,A_RINSE3,,0);
  }
  else if (data__->__action_list[__SFC_A_RINSE3].set) {
    __SET_VAR(data__->,A_RINSE3,,1);
  }
  if (data__->__action_list[__SFC_A_MOVE_CAR5].reset) {
    __SET_VAR(data__->,A_MOVE_CAR5,,0);
  }
  else if (data__->__action_list[__SFC_A_MOVE_CAR5].set) {
    __SET_VAR(data__->,A_MOVE_CAR5,,1);
  }
  if (data__->__action_list[__SFC_A_FINISH].reset) {
    __SET_VAR(data__->,A_FINISH,,0);
  }
  else if (data__->__action_list[__SFC_A_FINISH].set) {
    __SET_VAR(data__->,A_FINISH,,1);
  }
  if (data__->__action_list[__SFC_B_RINSE4].reset) {
    __SET_VAR(data__->,B_RINSE4,,0);
  }
  else if (data__->__action_list[__SFC_B_RINSE4].set) {
    __SET_VAR(data__->,B_RINSE4,,1);
  }
  if (data__->__action_list[__SFC_B_MOVE_CAR6].reset) {
    __SET_VAR(data__->,B_MOVE_CAR6,,0);
  }
  else if (data__->__action_list[__SFC_B_MOVE_CAR6].set) {
    __SET_VAR(data__->,B_MOVE_CAR6,,1);
  }
  if (data__->__action_list[__SFC_B_SOAP1].reset) {
    __SET_VAR(data__->,B_SOAP1,,0);
  }
  else if (data__->__action_list[__SFC_B_SOAP1].set) {
    __SET_VAR(data__->,B_SOAP1,,1);
  }
  if (data__->__action_list[__SFC_B_MOVE_CAR7].reset) {
    __SET_VAR(data__->,B_MOVE_CAR7,,0);
  }
  else if (data__->__action_list[__SFC_B_MOVE_CAR7].set) {
    __SET_VAR(data__->,B_MOVE_CAR7,,1);
  }
  if (data__->__action_list[__SFC_B_SCRUB2].reset) {
    __SET_VAR(data__->,B_SCRUB2,,0);
  }
  else if (data__->__action_list[__SFC_B_SCRUB2].set) {
    __SET_VAR(data__->,B_SCRUB2,,1);
  }
  if (data__->__action_list[__SFC_B_MOVE_CAR8].reset) {
    __SET_VAR(data__->,B_MOVE_CAR8,,0);
  }
  else if (data__->__action_list[__SFC_B_MOVE_CAR8].set) {
    __SET_VAR(data__->,B_MOVE_CAR8,,1);
  }
  if (data__->__action_list[__SFC_B_RINSE5].reset) {
    __SET_VAR(data__->,B_RINSE5,,0);
  }
  else if (data__->__action_list[__SFC_B_RINSE5].set) {
    __SET_VAR(data__->,B_RINSE5,,1);
  }
  if (data__->__action_list[__SFC_B_MOVE_CAR9].reset) {
    __SET_VAR(data__->,B_MOVE_CAR9,,0);
  }
  else if (data__->__action_list[__SFC_B_MOVE_CAR9].set) {
    __SET_VAR(data__->,B_MOVE_CAR9,,1);
  }
  if (data__->__action_list[__SFC_B_DRY0].reset) {
    __SET_VAR(data__->,B_DRY0,,0);
  }
  else if (data__->__action_list[__SFC_B_DRY0].set) {
    __SET_VAR(data__->,B_DRY0,,1);
  }
  if (data__->__action_list[__SFC_B_MOVE_CAR10].reset) {
    __SET_VAR(data__->,B_MOVE_CAR10,,0);
  }
  else if (data__->__action_list[__SFC_B_MOVE_CAR10].set) {
    __SET_VAR(data__->,B_MOVE_CAR10,,1);
  }
  if (data__->__action_list[__SFC_B_FINISH].reset) {
    __SET_VAR(data__->,B_FINISH,,0);
  }
  else if (data__->__action_list[__SFC_B_FINISH].set) {
    __SET_VAR(data__->,B_FINISH,,1);
  }
  if (data__->__action_list[__SFC_C_RINSE6].reset) {
    __SET_VAR(data__->,C_RINSE6,,0);
  }
  else if (data__->__action_list[__SFC_C_RINSE6].set) {
    __SET_VAR(data__->,C_RINSE6,,1);
  }
  if (data__->__action_list[__SFC_C_MOVE_CAR11].reset) {
    __SET_VAR(data__->,C_MOVE_CAR11,,0);
  }
  else if (data__->__action_list[__SFC_C_MOVE_CAR11].set) {
    __SET_VAR(data__->,C_MOVE_CAR11,,1);
  }
  if (data__->__action_list[__SFC_C_SOAP2].reset) {
    __SET_VAR(data__->,C_SOAP2,,0);
  }
  else if (data__->__action_list[__SFC_C_SOAP2].set) {
    __SET_VAR(data__->,C_SOAP2,,1);
  }
  if (data__->__action_list[__SFC_C_MOVE_CAR12].reset) {
    __SET_VAR(data__->,C_MOVE_CAR12,,0);
  }
  else if (data__->__action_list[__SFC_C_MOVE_CAR12].set) {
    __SET_VAR(data__->,C_MOVE_CAR12,,1);
  }
  if (data__->__action_list[__SFC_C_SCRUB3].reset) {
    __SET_VAR(data__->,C_SCRUB3,,0);
  }
  else if (data__->__action_list[__SFC_C_SCRUB3].set) {
    __SET_VAR(data__->,C_SCRUB3,,1);
  }
  if (data__->__action_list[__SFC_C_MOVE_CAR13].reset) {
    __SET_VAR(data__->,C_MOVE_CAR13,,0);
  }
  else if (data__->__action_list[__SFC_C_MOVE_CAR13].set) {
    __SET_VAR(data__->,C_MOVE_CAR13,,1);
  }
  if (data__->__action_list[__SFC_C_RINSE7].reset) {
    __SET_VAR(data__->,C_RINSE7,,0);
  }
  else if (data__->__action_list[__SFC_C_RINSE7].set) {
    __SET_VAR(data__->,C_RINSE7,,1);
  }
  if (data__->__action_list[__SFC_C_MOVE_CAR14].reset) {
    __SET_VAR(data__->,C_MOVE_CAR14,,0);
  }
  else if (data__->__action_list[__SFC_C_MOVE_CAR14].set) {
    __SET_VAR(data__->,C_MOVE_CAR14,,1);
  }
  if (data__->__action_list[__SFC_C_DRY1].reset) {
    __SET_VAR(data__->,C_DRY1,,0);
  }
  else if (data__->__action_list[__SFC_C_DRY1].set) {
    __SET_VAR(data__->,C_DRY1,,1);
  }
  if (data__->__action_list[__SFC_C_MOVE_CAR15].reset) {
    __SET_VAR(data__->,C_MOVE_CAR15,,0);
  }
  else if (data__->__action_list[__SFC_C_MOVE_CAR15].set) {
    __SET_VAR(data__->,C_MOVE_CAR15,,1);
  }
  if (data__->__action_list[__SFC_C_WAX_LIQUID0].reset) {
    __SET_VAR(data__->,C_WAX_LIQUID0,,0);
  }
  else if (data__->__action_list[__SFC_C_WAX_LIQUID0].set) {
    __SET_VAR(data__->,C_WAX_LIQUID0,,1);
  }
  if (data__->__action_list[__SFC_C_MOVE_CAR16].reset) {
    __SET_VAR(data__->,C_MOVE_CAR16,,0);
  }
  else if (data__->__action_list[__SFC_C_MOVE_CAR16].set) {
    __SET_VAR(data__->,C_MOVE_CAR16,,1);
  }
  if (data__->__action_list[__SFC_C_SCRUB1].reset) {
    __SET_VAR(data__->,C_SCRUB1,,0);
  }
  else if (data__->__action_list[__SFC_C_SCRUB1].set) {
    __SET_VAR(data__->,C_SCRUB1,,1);
  }
  if (data__->__action_list[__SFC_C_MOVE_CAR17].reset) {
    __SET_VAR(data__->,C_MOVE_CAR17,,0);
  }
  else if (data__->__action_list[__SFC_C_MOVE_CAR17].set) {
    __SET_VAR(data__->,C_MOVE_CAR17,,1);
  }
  if (data__->__action_list[__SFC_C_FINISH].reset) {
    __SET_VAR(data__->,C_FINISH,,0);
  }
  else if (data__->__action_list[__SFC_C_FINISH].set) {
    __SET_VAR(data__->,C_FINISH,,1);
  }
  if(__GET_VAR(data__->__action_list[__SFC_COMPUTE_FUNCTION_BLOCKS].state)) {
    __SET_VAR(data__->,_TMP_EQ14_OUT,,EQ__BOOL__SINT(
      (BOOL)__BOOL_LITERAL(TRUE),
      NULL,
      (UINT)2,
      (SINT)__GET_VAR(data__->SERVICE_SELECTION_BUTTON,),
      (SINT)__GET_VAR(data__->WASH_ONLY_SELECTION,)));
    __SET_VAR(data__->,_TMP_EQ17_OUT,,EQ__BOOL__SINT(
      (BOOL)__BOOL_LITERAL(TRUE),
      NULL,
      (UINT)2,
      (SINT)__GET_VAR(data__->SERVICE_SELECTION_BUTTON,),
      (SINT)__GET_VAR(data__->WASH_AND_DRY_SELECTION,)));
    __SET_VAR(data__->,_TMP_EQ20_OUT,,EQ__BOOL__SINT(
      (BOOL)__BOOL_LITERAL(TRUE),
      NULL,
      (UINT)2,
      (SINT)__GET_VAR(data__->SERVICE_SELECTION_BUTTON,),
      (SINT)__GET_VAR(data__->WASH_DRY_AND_WAX_SELECTION,)));
  }



  goto __end;

__end:
  return;
} // CAR_WASH_body__() 

// Steps undefinitions
#undef START
#undef __SFC_START
#undef SERVICE_SELECTION0
#undef __SFC_SERVICE_SELECTION0
#undef WASH_ONLY_A
#undef __SFC_WASH_ONLY_A
#undef RINSE2
#undef __SFC_RINSE2
#undef MOVE_CAR2
#undef __SFC_MOVE_CAR2
#undef SOAP0
#undef __SFC_SOAP0
#undef MOVE_CAR3
#undef __SFC_MOVE_CAR3
#undef SCRUB0
#undef __SFC_SCRUB0
#undef MOVE_CAR4
#undef __SFC_MOVE_CAR4
#undef RINSE3
#undef __SFC_RINSE3
#undef MOVE_CAR_5
#undef __SFC_MOVE_CAR_5
#undef WASH_AND_DRY_B
#undef __SFC_WASH_AND_DRY_B
#undef RINSE4
#undef __SFC_RINSE4
#undef MOVE_CAR6
#undef __SFC_MOVE_CAR6
#undef SOAP1
#undef __SFC_SOAP1
#undef MOVE_CAR7
#undef __SFC_MOVE_CAR7
#undef SCRUB2
#undef __SFC_SCRUB2
#undef MOVE_CAR8
#undef __SFC_MOVE_CAR8
#undef RINSE5
#undef __SFC_RINSE5
#undef MOVE_CAR9
#undef __SFC_MOVE_CAR9
#undef DRY0
#undef __SFC_DRY0
#undef MOVE_CAR10
#undef __SFC_MOVE_CAR10
#undef WASH_DRY_AND_WAX_C
#undef __SFC_WASH_DRY_AND_WAX_C
#undef RINSE6
#undef __SFC_RINSE6
#undef MOVE_CAR11
#undef __SFC_MOVE_CAR11
#undef SOAP2
#undef __SFC_SOAP2
#undef MOVE_CAR12
#undef __SFC_MOVE_CAR12
#undef SCRUB3
#undef __SFC_SCRUB3
#undef MOVE_CAR13
#undef __SFC_MOVE_CAR13
#undef RINSE7
#undef __SFC_RINSE7
#undef MOVE_CAR_14
#undef __SFC_MOVE_CAR_14
#undef DRY1
#undef __SFC_DRY1
#undef MOVE_CAR_15
#undef __SFC_MOVE_CAR_15
#undef WAX_LIQUID0
#undef __SFC_WAX_LIQUID0
#undef MOVE_CAR_16
#undef __SFC_MOVE_CAR_16
#undef SCRUB1
#undef __SFC_SCRUB1
#undef MOVE_CAR_17
#undef __SFC_MOVE_CAR_17

// Actions undefinitions
#undef __SFC_COMPUTE_FUNCTION_BLOCKS
#undef __SFC_AVAILABLE_LIGHT
#undef __SFC_CONVEYOR_LIGHT
#undef __SFC_CONVEYOR_MOTOR
#undef __SFC_WATER_SPRINKLER
#undef __SFC_SCRUBBERS
#undef __SFC_WAX_LIQUID
#undef __SFC_DRYERS
#undef __SFC_CAR_ON_START_SENSOR
#undef __SFC_SOAP_LIGHT
#undef __SFC_SCRUB_LIGHT
#undef __SFC_WAX_LIGHT
#undef __SFC_SOAP_SPRINKLER
#undef __SFC_A_RINSE2
#undef __SFC_A_MOVE_CAR2
#undef __SFC_A_SOAP0
#undef __SFC_A_MOVE_CAR3
#undef __SFC_A_SCRUB0
#undef __SFC_A_MOVE_CAR4
#undef __SFC_A_RINSE3
#undef __SFC_A_MOVE_CAR5
#undef __SFC_A_FINISH
#undef __SFC_B_RINSE4
#undef __SFC_B_MOVE_CAR6
#undef __SFC_B_SOAP1
#undef __SFC_B_MOVE_CAR7
#undef __SFC_B_SCRUB2
#undef __SFC_B_MOVE_CAR8
#undef __SFC_B_RINSE5
#undef __SFC_B_MOVE_CAR9
#undef __SFC_B_DRY0
#undef __SFC_B_MOVE_CAR10
#undef __SFC_B_FINISH
#undef __SFC_C_RINSE6
#undef __SFC_C_MOVE_CAR11
#undef __SFC_C_SOAP2
#undef __SFC_C_MOVE_CAR12
#undef __SFC_C_SCRUB3
#undef __SFC_C_MOVE_CAR13
#undef __SFC_C_RINSE7
#undef __SFC_C_MOVE_CAR14
#undef __SFC_C_DRY1
#undef __SFC_C_MOVE_CAR15
#undef __SFC_C_WAX_LIQUID0
#undef __SFC_C_MOVE_CAR16
#undef __SFC_C_SCRUB1
#undef __SFC_C_MOVE_CAR17
#undef __SFC_C_FINISH





