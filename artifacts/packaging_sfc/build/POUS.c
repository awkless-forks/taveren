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





void PYTHON_EVAL_init__(PYTHON_EVAL *data__, BOOL retain) {
  __INIT_VAR(data__->EN,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->ENO,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->TRIG,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->CODE,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->ACK,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->RESULT,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->STATE,0,retain)
  __INIT_VAR(data__->BUFFER,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->PREBUFFER,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->TRIGM1,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->TRIGGED,__BOOL_LITERAL(FALSE),retain)
}

// Code part
void PYTHON_EVAL_body__(PYTHON_EVAL *data__) {
  // Control execution
  if (!__GET_VAR(data__->EN)) {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(FALSE));
    return;
  }
  else {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(TRUE));
  }
  // Initialise TEMP variables

  __IL_DEFVAR_T __IL_DEFVAR;
  __IL_DEFVAR_T __IL_DEFVAR_BACK;
  #define GetFbVar(var,...) __GET_VAR(data__->var,__VA_ARGS__)
  #define SetFbVar(var,val,...) __SET_VAR(data__->,var,__VA_ARGS__,val)
extern void __PythonEvalFB(int, PYTHON_EVAL*);__PythonEvalFB(0, data__);
  #undef GetFbVar
  #undef SetFbVar
;

  goto __end;

__end:
  return;
} // PYTHON_EVAL_body__() 





void PYTHON_POLL_init__(PYTHON_POLL *data__, BOOL retain) {
  __INIT_VAR(data__->EN,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->ENO,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->TRIG,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->CODE,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->ACK,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->RESULT,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->STATE,0,retain)
  __INIT_VAR(data__->BUFFER,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->PREBUFFER,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->TRIGM1,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->TRIGGED,__BOOL_LITERAL(FALSE),retain)
}

// Code part
void PYTHON_POLL_body__(PYTHON_POLL *data__) {
  // Control execution
  if (!__GET_VAR(data__->EN)) {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(FALSE));
    return;
  }
  else {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(TRUE));
  }
  // Initialise TEMP variables

  __IL_DEFVAR_T __IL_DEFVAR;
  __IL_DEFVAR_T __IL_DEFVAR_BACK;
  #define GetFbVar(var,...) __GET_VAR(data__->var,__VA_ARGS__)
  #define SetFbVar(var,val,...) __SET_VAR(data__->,var,__VA_ARGS__,val)
extern void __PythonEvalFB(int, PYTHON_EVAL*);__PythonEvalFB(1,(PYTHON_EVAL*)(void*)data__);
  #undef GetFbVar
  #undef SetFbVar
;

  goto __end;

__end:
  return;
} // PYTHON_POLL_body__() 





void PYTHON_GEAR_init__(PYTHON_GEAR *data__, BOOL retain) {
  __INIT_VAR(data__->EN,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->ENO,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->N,0,retain)
  __INIT_VAR(data__->TRIG,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->CODE,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->ACK,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->RESULT,__STRING_LITERAL(0,""),retain)
  PYTHON_EVAL_init__(&data__->PY_EVAL,retain);
  __INIT_VAR(data__->COUNTER,0,retain)
  __INIT_VAR(data__->_TMP_ADD10_OUT,0,retain)
  __INIT_VAR(data__->_TMP_EQ13_OUT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->_TMP_SEL15_OUT,0,retain)
  __INIT_VAR(data__->_TMP_AND7_OUT,__BOOL_LITERAL(FALSE),retain)
}

// Code part
void PYTHON_GEAR_body__(PYTHON_GEAR *data__) {
  // Control execution
  if (!__GET_VAR(data__->EN)) {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(FALSE));
    return;
  }
  else {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(TRUE));
  }
  // Initialise TEMP variables

  __SET_VAR(data__->,_TMP_ADD10_OUT,,ADD__UINT__UINT(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (UINT)2,
    (UINT)__GET_VAR(data__->COUNTER,),
    (UINT)1));
  __SET_VAR(data__->,_TMP_EQ13_OUT,,EQ__BOOL__UINT(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (UINT)2,
    (UINT)__GET_VAR(data__->N,),
    (UINT)__GET_VAR(data__->_TMP_ADD10_OUT,)));
  __SET_VAR(data__->,_TMP_SEL15_OUT,,SEL__UINT__BOOL__UINT__UINT(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (BOOL)__GET_VAR(data__->_TMP_EQ13_OUT,),
    (UINT)__GET_VAR(data__->_TMP_ADD10_OUT,),
    (UINT)0));
  __SET_VAR(data__->,COUNTER,,__GET_VAR(data__->_TMP_SEL15_OUT,));
  __SET_VAR(data__->,_TMP_AND7_OUT,,AND__BOOL__BOOL(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (UINT)2,
    (BOOL)__GET_VAR(data__->_TMP_EQ13_OUT,),
    (BOOL)__GET_VAR(data__->TRIG,)));
  __SET_VAR(data__->PY_EVAL.,TRIG,,__GET_VAR(data__->_TMP_AND7_OUT,));
  __SET_VAR(data__->PY_EVAL.,CODE,,__GET_VAR(data__->CODE,));
  PYTHON_EVAL_body__(&data__->PY_EVAL);
  __SET_VAR(data__->,ACK,,__GET_VAR(data__->PY_EVAL.ACK,));
  __SET_VAR(data__->,RESULT,,__GET_VAR(data__->PY_EVAL.RESULT,));

  goto __end;

__end:
  return;
} // PYTHON_GEAR_body__() 





void LAMP_init__(LAMP *data__, BOOL retain) {
  __INIT_VAR(data__->START_BUTTON,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->RED_LIGHT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->CONVEYOR_MOTOR,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->PRODUCT_SENSOR,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->PRODUCT_EMPTY_SENSOR,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->GREEN_LIGHT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->YELLOW_LIGHT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->PRODUCT_VALVE,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->STOP,__BOOL_LITERAL(FALSE),retain)
  UINT i;
  data__->__nb_steps = 5;
  static const STEP temp_step = {{0, 0}, 0, {{0, 0}, 0}};
  for(i = 0; i < data__->__nb_steps; i++) {
    data__->__step_list[i] = temp_step;
  }
  __SET_VAR(data__->,__step_list[0].X,,1);
  data__->__nb_actions = 6;
  static const ACTION temp_action = {0, {0, 0}, 0, 0, {0, 0}, {0, 0}};
  for(i = 0; i < data__->__nb_actions; i++) {
    data__->__action_list[i] = temp_action;
  }
  data__->__nb_transitions = 5;
  data__->__lasttick_time = __CURRENT_TIME;
}

// Steps definitions
#define START __step_list[0]
#define __SFC_START 0
#define CONVEYOR_START __step_list[1]
#define __SFC_CONVEYOR_START 1
#define PRODUCT_DETECTED __step_list[2]
#define __SFC_PRODUCT_DETECTED 2
#define PACKAGE __step_list[3]
#define __SFC_PACKAGE 3
#define STOP_PACKAGING __step_list[4]
#define __SFC_STOP_PACKAGING 4

// Actions definitions
#define __SFC_RED_LIGHT 0
#define __SFC_CONVEYOR_MOTOR 1
#define __SFC_YELLOW_LIGHT 2
#define __SFC_GREEN_LIGHT 3
#define __SFC_PRODUCT_VALVE 4
#define __SFC_STOP 5

// Code part
void LAMP_body__(LAMP *data__) {
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
    __SET_VAR(data__->,__transition_list[0],,__GET_VAR(data__->START_BUTTON,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[0],,__GET_VAR(data__->__transition_list[0]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[0],,__GET_VAR(data__->START_BUTTON,));
    }
    __SET_VAR(data__->,__transition_list[0],,0);
  }
  if (__GET_VAR(data__->CONVEYOR_START.X)) {
    __SET_VAR(data__->,__transition_list[1],,__GET_VAR(data__->PRODUCT_SENSOR,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[1],,__GET_VAR(data__->__transition_list[1]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[1],,__GET_VAR(data__->PRODUCT_SENSOR,));
    }
    __SET_VAR(data__->,__transition_list[1],,0);
  }
  if (__GET_VAR(data__->PRODUCT_DETECTED.X)) {
    __SET_VAR(data__->,__transition_list[2],,__GET_VAR(data__->PRODUCT_EMPTY_SENSOR,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[2],,__GET_VAR(data__->__transition_list[2]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[2],,__GET_VAR(data__->PRODUCT_EMPTY_SENSOR,));
    }
    __SET_VAR(data__->,__transition_list[2],,0);
  }
  if (__GET_VAR(data__->PACKAGE.X)) {
    __SET_VAR(data__->,__transition_list[3],,__GET_VAR(data__->STOP,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[3],,__GET_VAR(data__->__transition_list[3]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[3],,__GET_VAR(data__->STOP,));
    }
    __SET_VAR(data__->,__transition_list[3],,0);
  }
  if (__GET_VAR(data__->STOP_PACKAGING.X)) {
    __SET_VAR(data__->,__transition_list[4],,__GET_VAR(data__->START_BUTTON,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[4],,__GET_VAR(data__->__transition_list[4]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[4],,__GET_VAR(data__->START_BUTTON,));
    }
    __SET_VAR(data__->,__transition_list[4],,0);
  }

  // Transitions reset steps
  if (__GET_VAR(data__->__transition_list[0])) {
    __SET_VAR(data__->,START.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[1])) {
    __SET_VAR(data__->,CONVEYOR_START.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[2])) {
    __SET_VAR(data__->,PRODUCT_DETECTED.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[3])) {
    __SET_VAR(data__->,PACKAGE.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[4])) {
    __SET_VAR(data__->,STOP_PACKAGING.X,,0);
  }

  // Transitions set steps
  if (__GET_VAR(data__->__transition_list[0])) {
    __SET_VAR(data__->,CONVEYOR_START.X,,1);
    data__->CONVEYOR_START.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[1])) {
    __SET_VAR(data__->,PRODUCT_DETECTED.X,,1);
    data__->PRODUCT_DETECTED.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[2])) {
    __SET_VAR(data__->,PACKAGE.X,,1);
    data__->PACKAGE.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[3])) {
    __SET_VAR(data__->,STOP_PACKAGING.X,,1);
    data__->STOP_PACKAGING.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[4])) {
    __SET_VAR(data__->,CONVEYOR_START.X,,1);
    data__->CONVEYOR_START.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }

  // Steps association
  // START action associations
  {
    char active = __GET_VAR(data__->START.X);
    char activated = active && !data__->START.prev_state;
    char desactivated = !active && data__->START.prev_state;

    if (active)       {__SET_VAR(data__->,RED_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,RED_LIGHT,,0);};

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active)       {data__->__action_list[__SFC_YELLOW_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_GREEN_LIGHT].reset = 1;}

  }

  // CONVEYOR_START action associations
  {
    char active = __GET_VAR(data__->CONVEYOR_START.X);
    char activated = active && !data__->CONVEYOR_START.prev_state;
    char desactivated = !active && data__->CONVEYOR_START.prev_state;

    if (active)       {__SET_VAR(data__->,CONVEYOR_MOTOR,,1);};
    if (desactivated) {__SET_VAR(data__->,CONVEYOR_MOTOR,,0);};

    if (active)       {data__->__action_list[__SFC_RED_LIGHT].reset = 1;}

    if (active)       {__SET_VAR(data__->,GREEN_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,GREEN_LIGHT,,0);};

  }

  // PRODUCT_DETECTED action associations
  {
    char active = __GET_VAR(data__->PRODUCT_DETECTED.X);
    char activated = active && !data__->PRODUCT_DETECTED.prev_state;
    char desactivated = !active && data__->PRODUCT_DETECTED.prev_state;

    if (active)       {data__->__action_list[__SFC_CONVEYOR_MOTOR].reset = 1;}

    if (active)       {data__->__action_list[__SFC_GREEN_LIGHT].reset = 1;}

    if (active)       {__SET_VAR(data__->,RED_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,RED_LIGHT,,0);};

  }

  // PACKAGE action associations
  {
    char active = __GET_VAR(data__->PACKAGE.X);
    char activated = active && !data__->PACKAGE.prev_state;
    char desactivated = !active && data__->PACKAGE.prev_state;

    if (active)       {__SET_VAR(data__->,PRODUCT_VALVE,,1);};
    if (desactivated) {__SET_VAR(data__->,PRODUCT_VALVE,,0);};

    if (active)       {__SET_VAR(data__->,YELLOW_LIGHT,,1);};
    if (desactivated) {__SET_VAR(data__->,YELLOW_LIGHT,,0);};

    if (active && __time_cmp(data__->PACKAGE.T.value, __time_to_timespec(1, 0, 25, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,STOP,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,STOP,,0);};

  }

  // STOP_PACKAGING action associations
  {
    char active = __GET_VAR(data__->STOP_PACKAGING.X);
    char activated = active && !data__->STOP_PACKAGING.prev_state;
    char desactivated = !active && data__->STOP_PACKAGING.prev_state;

    if (active)       {data__->__action_list[__SFC_PRODUCT_VALVE].reset = 1;}

    if (active)       {data__->__action_list[__SFC_YELLOW_LIGHT].reset = 1;}

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
  if (data__->__action_list[__SFC_RED_LIGHT].reset) {
    __SET_VAR(data__->,RED_LIGHT,,0);
  }
  else if (data__->__action_list[__SFC_RED_LIGHT].set) {
    __SET_VAR(data__->,RED_LIGHT,,1);
  }
  if (data__->__action_list[__SFC_CONVEYOR_MOTOR].reset) {
    __SET_VAR(data__->,CONVEYOR_MOTOR,,0);
  }
  else if (data__->__action_list[__SFC_CONVEYOR_MOTOR].set) {
    __SET_VAR(data__->,CONVEYOR_MOTOR,,1);
  }
  if (data__->__action_list[__SFC_YELLOW_LIGHT].reset) {
    __SET_VAR(data__->,YELLOW_LIGHT,,0);
  }
  else if (data__->__action_list[__SFC_YELLOW_LIGHT].set) {
    __SET_VAR(data__->,YELLOW_LIGHT,,1);
  }
  if (data__->__action_list[__SFC_GREEN_LIGHT].reset) {
    __SET_VAR(data__->,GREEN_LIGHT,,0);
  }
  else if (data__->__action_list[__SFC_GREEN_LIGHT].set) {
    __SET_VAR(data__->,GREEN_LIGHT,,1);
  }
  if (data__->__action_list[__SFC_PRODUCT_VALVE].reset) {
    __SET_VAR(data__->,PRODUCT_VALVE,,0);
  }
  else if (data__->__action_list[__SFC_PRODUCT_VALVE].set) {
    __SET_VAR(data__->,PRODUCT_VALVE,,1);
  }
  if (data__->__action_list[__SFC_STOP].reset) {
    __SET_VAR(data__->,STOP,,0);
  }
  else if (data__->__action_list[__SFC_STOP].set) {
    __SET_VAR(data__->,STOP,,1);
  }


  goto __end;

__end:
  return;
} // LAMP_body__() 

// Steps undefinitions
#undef START
#undef __SFC_START
#undef CONVEYOR_START
#undef __SFC_CONVEYOR_START
#undef PRODUCT_DETECTED
#undef __SFC_PRODUCT_DETECTED
#undef PACKAGE
#undef __SFC_PACKAGE
#undef STOP_PACKAGING
#undef __SFC_STOP_PACKAGING

// Actions undefinitions
#undef __SFC_RED_LIGHT
#undef __SFC_CONVEYOR_MOTOR
#undef __SFC_YELLOW_LIGHT
#undef __SFC_GREEN_LIGHT
#undef __SFC_PRODUCT_VALVE
#undef __SFC_STOP





