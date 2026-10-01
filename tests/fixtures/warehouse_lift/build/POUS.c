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





void LIFT_init__(LIFT *data__, BOOL retain) {
  __INIT_VAR(data__->ASSIGNED_PALLET_RACK,6,retain)
  __INIT_VAR(data__->LIFT_UP_MOTOR,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->LIFT_DOWN_MOTOR,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->CONVEYOR_MOTOR,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->CURRENT_RACK,0,retain)
  __INIT_VAR(data__->INITIAL_RACK,0,retain)
  TON_init__(&data__->TON0,retain);
  TON_init__(&data__->TON1,retain);
  __INIT_VAR(data__->_TMP_GT5_OUT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->_TMP_EQ12_OUT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->_TMP_EQ23_OUT,__BOOL_LITERAL(FALSE),retain)
  UINT i;
  data__->__nb_steps = 5;
  static const STEP temp_step = {{0, 0}, 0, {{0, 0}, 0}};
  for(i = 0; i < data__->__nb_steps; i++) {
    data__->__step_list[i] = temp_step;
  }
  __SET_VAR(data__->,__step_list[0].X,,1);
  __SET_VAR(data__->,__step_list[2].X,,1);
  __SET_VAR(data__->,__step_list[4].X,,1);
  data__->__nb_actions = 4;
  static const ACTION temp_action = {0, {0, 0}, 0, 0, {0, 0}, {0, 0}};
  for(i = 0; i < data__->__nb_actions; i++) {
    data__->__action_list[i] = temp_action;
  }
  data__->__nb_transitions = 5;
  data__->__lasttick_time = __CURRENT_TIME;
}

// Steps definitions
#define INITIALIZE __step_list[0]
#define __SFC_INITIALIZE 0
#define GO_UP __step_list[1]
#define __SFC_GO_UP 1
#define DELIVER_BOX __step_list[2]
#define __SFC_DELIVER_BOX 2
#define GO_DOWN __step_list[3]
#define __SFC_GO_DOWN 3
#define GET_BOX __step_list[4]
#define __SFC_GET_BOX 4

// Actions definitions
#define __SFC_COMPUTE_FUNCTION_BLOCKS 0
#define __SFC_LIFT_UP_MOTOR 1
#define __SFC_LIFT_DOWN_MOTOR 2
#define __SFC_CONVEYOR_MOTOR 3

// Code part
void LIFT_body__(LIFT *data__) {
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
  if (__GET_VAR(data__->INITIALIZE.X)) {
    __SET_VAR(data__->,__transition_list[0],,__GET_VAR(data__->_TMP_GT5_OUT,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[0],,__GET_VAR(data__->__transition_list[0]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[0],,__GET_VAR(data__->_TMP_GT5_OUT,));
    }
    __SET_VAR(data__->,__transition_list[0],,0);
  }
  if (__GET_VAR(data__->GO_UP.X)) {
    __SET_VAR(data__->,__transition_list[1],,__GET_VAR(data__->_TMP_EQ12_OUT,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[1],,__GET_VAR(data__->__transition_list[1]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[1],,__GET_VAR(data__->_TMP_EQ12_OUT,));
    }
    __SET_VAR(data__->,__transition_list[1],,0);
  }
  if (__GET_VAR(data__->DELIVER_BOX.X)) {
    __SET_VAR(data__->,__transition_list[2],,__GET_VAR(data__->TON0.Q,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[2],,__GET_VAR(data__->__transition_list[2]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[2],,__GET_VAR(data__->TON0.Q,));
    }
    __SET_VAR(data__->,__transition_list[2],,0);
  }
  if (__GET_VAR(data__->GO_DOWN.X)) {
    __SET_VAR(data__->,__transition_list[3],,__GET_VAR(data__->_TMP_EQ23_OUT,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[3],,__GET_VAR(data__->__transition_list[3]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[3],,__GET_VAR(data__->_TMP_EQ23_OUT,));
    }
    __SET_VAR(data__->,__transition_list[3],,0);
  }
  if (__GET_VAR(data__->GET_BOX.X)) {
    __SET_VAR(data__->,__transition_list[4],,__GET_VAR(data__->TON1.Q,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[4],,__GET_VAR(data__->__transition_list[4]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[4],,__GET_VAR(data__->TON1.Q,));
    }
    __SET_VAR(data__->,__transition_list[4],,0);
  }

  // Transitions reset steps
  if (__GET_VAR(data__->__transition_list[0])) {
    __SET_VAR(data__->,INITIALIZE.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[1])) {
    __SET_VAR(data__->,GO_UP.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[2])) {
    __SET_VAR(data__->,DELIVER_BOX.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[3])) {
    __SET_VAR(data__->,GO_DOWN.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[4])) {
    __SET_VAR(data__->,GET_BOX.X,,0);
  }

  // Transitions set steps
  if (__GET_VAR(data__->__transition_list[0])) {
    __SET_VAR(data__->,GO_UP.X,,1);
    data__->GO_UP.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[1])) {
    __SET_VAR(data__->,DELIVER_BOX.X,,1);
    data__->DELIVER_BOX.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[2])) {
    __SET_VAR(data__->,GO_DOWN.X,,1);
    data__->GO_DOWN.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[3])) {
    __SET_VAR(data__->,GET_BOX.X,,1);
    data__->GET_BOX.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[4])) {
    __SET_VAR(data__->,GO_UP.X,,1);
    data__->GO_UP.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }

  // Steps association
  // INITIALIZE action associations
  {
    char active = __GET_VAR(data__->INITIALIZE.X);
    char activated = active && !data__->INITIALIZE.prev_state;
    char desactivated = !active && data__->INITIALIZE.prev_state;

    if (active)       {data__->__action_list[__SFC_LIFT_UP_MOTOR].reset = 1;}

    if (active)       {data__->__action_list[__SFC_LIFT_DOWN_MOTOR].reset = 1;}

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active)       {data__->__action_list[__SFC_COMPUTE_FUNCTION_BLOCKS].set = 1;}

  }

  // GO_UP action associations
  {
    char active = __GET_VAR(data__->GO_UP.X);
    char activated = active && !data__->GO_UP.prev_state;
    char desactivated = !active && data__->GO_UP.prev_state;

    if (active)       {__SET_VAR(data__->,LIFT_UP_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,LIFT_UP_MOTOR,,0);};

  }

  // DELIVER_BOX action associations
  {
    char active = __GET_VAR(data__->DELIVER_BOX.X);
    char activated = active && !data__->DELIVER_BOX.prev_state;
    char desactivated = !active && data__->DELIVER_BOX.prev_state;

    if (active)       {data__->__action_list[__SFC_LIFT_UP_MOTOR].reset = 1;}

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

  }

  // GO_DOWN action associations
  {
    char active = __GET_VAR(data__->GO_DOWN.X);
    char activated = active && !data__->GO_DOWN.prev_state;
    char desactivated = !active && data__->GO_DOWN.prev_state;

    if (active)       {__SET_VAR(data__->,LIFT_DOWN_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,LIFT_DOWN_MOTOR,,0);};

  }

  // GET_BOX action associations
  {
    char active = __GET_VAR(data__->GET_BOX.X);
    char activated = active && !data__->GET_BOX.prev_state;
    char desactivated = !active && data__->GET_BOX.prev_state;

    if (active)       {data__->__action_list[__SFC_LIFT_DOWN_MOTOR].reset = 1;}

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

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
  if (data__->__action_list[__SFC_LIFT_UP_MOTOR].reset) {
    __SET_VAR(data__->,LIFT_UP_MOTOR,,0);
  }
  else if (data__->__action_list[__SFC_LIFT_UP_MOTOR].set) {
    __SET_VAR(data__->,LIFT_UP_MOTOR,,1);
  }
  if (data__->__action_list[__SFC_LIFT_DOWN_MOTOR].reset) {
    __SET_VAR(data__->,LIFT_DOWN_MOTOR,,0);
  }
  else if (data__->__action_list[__SFC_LIFT_DOWN_MOTOR].set) {
    __SET_VAR(data__->,LIFT_DOWN_MOTOR,,1);
  }
  if (data__->__action_list[__SFC_CONVEYOR_MOTOR].reset) {
    __SET_VAR(data__->,CONVEYOR_MOTOR,,0);
  }
  else if (data__->__action_list[__SFC_CONVEYOR_MOTOR].set) {
    __SET_VAR(data__->,CONVEYOR_MOTOR,,1);
  }
  if(__GET_VAR(data__->__action_list[__SFC_COMPUTE_FUNCTION_BLOCKS].state)) {
    __SET_VAR(data__->,_TMP_GT5_OUT,,GT__BOOL__SINT(
      (BOOL)__BOOL_LITERAL(TRUE),
      NULL,
      (UINT)2,
      (SINT)__GET_VAR(data__->ASSIGNED_PALLET_RACK,),
      (SINT)__GET_VAR(data__->CURRENT_RACK,)));
    __SET_VAR(data__->,_TMP_EQ12_OUT,,EQ__BOOL__SINT(
      (BOOL)__BOOL_LITERAL(TRUE),
      NULL,
      (UINT)2,
      (SINT)__GET_VAR(data__->ASSIGNED_PALLET_RACK,),
      (SINT)__GET_VAR(data__->CURRENT_RACK,)));
    __SET_VAR(data__->TON0.,IN,,__GET_VAR(data__->CONVEYOR_MOTOR,));
    __SET_VAR(data__->TON0.,PT,,__time_to_timespec(1, 0, 5, 0, 0, 0));
    TON_body__(&data__->TON0);
    __SET_VAR(data__->,_TMP_EQ23_OUT,,EQ__BOOL__SINT(
      (BOOL)__BOOL_LITERAL(TRUE),
      NULL,
      (UINT)2,
      (SINT)__GET_VAR(data__->CURRENT_RACK,),
      (SINT)__GET_VAR(data__->INITIAL_RACK,)));
    __SET_VAR(data__->TON1.,IN,,__GET_VAR(data__->CONVEYOR_MOTOR,));
    __SET_VAR(data__->TON1.,PT,,__time_to_timespec(1, 0, 5, 0, 0, 0));
    TON_body__(&data__->TON1);
  }



  goto __end;

__end:
  return;
} // LIFT_body__() 

// Steps undefinitions
#undef INITIALIZE
#undef __SFC_INITIALIZE
#undef GO_UP
#undef __SFC_GO_UP
#undef DELIVER_BOX
#undef __SFC_DELIVER_BOX
#undef GO_DOWN
#undef __SFC_GO_DOWN
#undef GET_BOX
#undef __SFC_GET_BOX

// Actions undefinitions
#undef __SFC_COMPUTE_FUNCTION_BLOCKS
#undef __SFC_LIFT_UP_MOTOR
#undef __SFC_LIFT_DOWN_MOTOR
#undef __SFC_CONVEYOR_MOTOR





