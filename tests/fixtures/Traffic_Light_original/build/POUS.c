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





void GETBOOLSTRING_init__(GETBOOLSTRING *data__, BOOL retain) {
  __INIT_VAR(data__->EN,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->ENO,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->VALUE,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->CODE,__STRING_LITERAL(0,""),retain)
}

// Code part
void GETBOOLSTRING_body__(GETBOOLSTRING *data__) {
  // Control execution
  if (!__GET_VAR(data__->EN)) {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(FALSE));
    return;
  }
  else {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(TRUE));
  }
  // Initialise TEMP variables

  if (__GET_VAR(data__->VALUE,)) {
    __SET_VAR(data__->,CODE,,__STRING_LITERAL(4,"True"));
  } else {
    __SET_VAR(data__->,CODE,,__STRING_LITERAL(5,"False"));
  };

  goto __end;

__end:
  return;
} // GETBOOLSTRING_body__() 





void BUTTON_init__(BUTTON *data__, BOOL retain) {
  __INIT_VAR(data__->EN,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->ENO,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->ID,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->BACK_ID,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->SELE_ID,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->TOGGLE,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->SET_STATE,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->STATE_IN,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->STATE_OUT,__BOOL_LITERAL(FALSE),retain)
  PYTHON_EVAL_init__(&data__->INIT_COMMAND,retain);
  GETBOOLSTRING_init__(&data__->GETBUTTONSTATE,retain);
  PYTHON_EVAL_init__(&data__->SETSTATE_COMMAND,retain);
  PYTHON_POLL_init__(&data__->GETSTATE_COMMAND,retain);
  GETBOOLSTRING_init__(&data__->GETBUTTONTOGGLE,retain);
  __INIT_VAR(data__->_TMP_CONCAT2_OUT,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->_TMP_CONCAT22_OUT,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->_TMP_STRING_TO_INT25_OUT,0,retain)
  __INIT_VAR(data__->_TMP_INT_TO_BOOL26_OUT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->_TMP_AND31_OUT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->_TMP_CONCAT7_OUT,__STRING_LITERAL(0,""),retain)
}

// Code part
void BUTTON_body__(BUTTON *data__) {
  // Control execution
  if (!__GET_VAR(data__->EN)) {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(FALSE));
    return;
  }
  else {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(TRUE));
  }
  // Initialise TEMP variables

  __SET_VAR(data__->GETBUTTONTOGGLE.,VALUE,,__GET_VAR(data__->TOGGLE,));
  GETBOOLSTRING_body__(&data__->GETBUTTONTOGGLE);
  __SET_VAR(data__->,_TMP_CONCAT2_OUT,,CONCAT(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (UINT)7,
    (STRING)__STRING_LITERAL(37,"createSVGUIControl(\"button\",back_id=\""),
    (STRING)__GET_VAR(data__->BACK_ID,),
    (STRING)__STRING_LITERAL(11,"\",sele_id=\""),
    (STRING)__GET_VAR(data__->SELE_ID,),
    (STRING)__STRING_LITERAL(9,"\",toggle="),
    (STRING)__GET_VAR(data__->GETBUTTONTOGGLE.CODE,),
    (STRING)__STRING_LITERAL(13,",active=True)")));
  __SET_VAR(data__->INIT_COMMAND.,TRIG,,__BOOL_LITERAL(TRUE));
  __SET_VAR(data__->INIT_COMMAND.,CODE,,__GET_VAR(data__->_TMP_CONCAT2_OUT,));
  PYTHON_EVAL_body__(&data__->INIT_COMMAND);
  __SET_VAR(data__->,ID,,__GET_VAR(data__->INIT_COMMAND.RESULT,));
  __SET_VAR(data__->,_TMP_CONCAT22_OUT,,CONCAT(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (UINT)3,
    (STRING)__STRING_LITERAL(12,"int(getAttr("),
    (STRING)__GET_VAR(data__->ID,),
    (STRING)__STRING_LITERAL(16,",\"state\",False))")));
  __SET_VAR(data__->GETSTATE_COMMAND.,TRIG,,__GET_VAR(data__->INIT_COMMAND.ACK,));
  __SET_VAR(data__->GETSTATE_COMMAND.,CODE,,__GET_VAR(data__->_TMP_CONCAT22_OUT,));
  PYTHON_POLL_body__(&data__->GETSTATE_COMMAND);
  __SET_VAR(data__->,_TMP_STRING_TO_INT25_OUT,,STRING_TO_INT(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (STRING)__GET_VAR(data__->GETSTATE_COMMAND.RESULT,)));
  __SET_VAR(data__->,_TMP_INT_TO_BOOL26_OUT,,INT_TO_BOOL(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (INT)__GET_VAR(data__->_TMP_STRING_TO_INT25_OUT,)));
  __SET_VAR(data__->,STATE_OUT,,__GET_VAR(data__->_TMP_INT_TO_BOOL26_OUT,));
  __SET_VAR(data__->,_TMP_AND31_OUT,,AND__BOOL__BOOL(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (UINT)2,
    (BOOL)__GET_VAR(data__->INIT_COMMAND.ACK,),
    (BOOL)__GET_VAR(data__->SET_STATE,)));
  __SET_VAR(data__->GETBUTTONSTATE.,VALUE,,__GET_VAR(data__->STATE_IN,));
  GETBOOLSTRING_body__(&data__->GETBUTTONSTATE);
  __SET_VAR(data__->,_TMP_CONCAT7_OUT,,CONCAT(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (UINT)5,
    (STRING)__STRING_LITERAL(8,"setAttr("),
    (STRING)__GET_VAR(data__->ID,),
    (STRING)__STRING_LITERAL(9,",\"state\","),
    (STRING)__GET_VAR(data__->GETBUTTONSTATE.CODE,),
    (STRING)__STRING_LITERAL(1,")")));
  __SET_VAR(data__->SETSTATE_COMMAND.,TRIG,,__GET_VAR(data__->_TMP_AND31_OUT,));
  __SET_VAR(data__->SETSTATE_COMMAND.,CODE,,__GET_VAR(data__->_TMP_CONCAT7_OUT,));
  PYTHON_EVAL_body__(&data__->SETSTATE_COMMAND);

  goto __end;

__end:
  return;
} // BUTTON_body__() 





void LED_init__(LED *data__, BOOL retain) {
  __INIT_VAR(data__->EN,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->ENO,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->ID,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->BACK_ID,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->SELE_ID,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->STATE_IN,__BOOL_LITERAL(FALSE),retain)
  PYTHON_EVAL_init__(&data__->INIT_COMMAND,retain);
  PYTHON_POLL_init__(&data__->SETSTATE_COMMAND,retain);
  GETBOOLSTRING_init__(&data__->GETLEDSTATE,retain);
  __INIT_VAR(data__->_TMP_CONCAT2_OUT,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->_TMP_CONCAT7_OUT,__STRING_LITERAL(0,""),retain)
}

// Code part
void LED_body__(LED *data__) {
  // Control execution
  if (!__GET_VAR(data__->EN)) {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(FALSE));
    return;
  }
  else {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(TRUE));
  }
  // Initialise TEMP variables

  __SET_VAR(data__->,_TMP_CONCAT2_OUT,,CONCAT(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (UINT)5,
    (STRING)__STRING_LITERAL(37,"createSVGUIControl(\"button\",back_id=\""),
    (STRING)__GET_VAR(data__->BACK_ID,),
    (STRING)__STRING_LITERAL(11,"\",sele_id=\""),
    (STRING)__GET_VAR(data__->SELE_ID,),
    (STRING)__STRING_LITERAL(27,"\",toggle=True,active=False)")));
  __SET_VAR(data__->INIT_COMMAND.,TRIG,,__BOOL_LITERAL(TRUE));
  __SET_VAR(data__->INIT_COMMAND.,CODE,,__GET_VAR(data__->_TMP_CONCAT2_OUT,));
  PYTHON_EVAL_body__(&data__->INIT_COMMAND);
  __SET_VAR(data__->,ID,,__GET_VAR(data__->INIT_COMMAND.RESULT,));
  __SET_VAR(data__->GETLEDSTATE.,VALUE,,__GET_VAR(data__->STATE_IN,));
  GETBOOLSTRING_body__(&data__->GETLEDSTATE);
  __SET_VAR(data__->,_TMP_CONCAT7_OUT,,CONCAT(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (UINT)5,
    (STRING)__STRING_LITERAL(8,"setAttr("),
    (STRING)__GET_VAR(data__->ID,),
    (STRING)__STRING_LITERAL(9,",\"state\","),
    (STRING)__GET_VAR(data__->GETLEDSTATE.CODE,),
    (STRING)__STRING_LITERAL(1,")")));
  __SET_VAR(data__->SETSTATE_COMMAND.,TRIG,,__GET_VAR(data__->INIT_COMMAND.ACK,));
  __SET_VAR(data__->SETSTATE_COMMAND.,CODE,,__GET_VAR(data__->_TMP_CONCAT7_OUT,));
  PYTHON_POLL_body__(&data__->SETSTATE_COMMAND);

  goto __end;

__end:
  return;
} // LED_body__() 





void TEXTCTRL_init__(TEXTCTRL *data__, BOOL retain) {
  __INIT_VAR(data__->EN,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->ENO,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->ID,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->BACK_ID,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->SET_TEXT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->TEXT,__STRING_LITERAL(0,""),retain)
  PYTHON_EVAL_init__(&data__->SVGUI_TEXTCTRL,retain);
  PYTHON_EVAL_init__(&data__->SETSTATE_COMMAND,retain);
  __INIT_VAR(data__->_TMP_CONCAT1_OUT,__STRING_LITERAL(0,""),retain)
  __INIT_VAR(data__->_TMP_AND31_OUT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->_TMP_CONCAT12_OUT,__STRING_LITERAL(0,""),retain)
}

// Code part
void TEXTCTRL_body__(TEXTCTRL *data__) {
  // Control execution
  if (!__GET_VAR(data__->EN)) {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(FALSE));
    return;
  }
  else {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(TRUE));
  }
  // Initialise TEMP variables

  __SET_VAR(data__->,_TMP_CONCAT1_OUT,,CONCAT(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (UINT)3,
    (STRING)__STRING_LITERAL(43,"createSVGUIControl(\"textControl\", back_id=\""),
    (STRING)__GET_VAR(data__->BACK_ID,),
    (STRING)__STRING_LITERAL(2,"\")")));
  __SET_VAR(data__->SVGUI_TEXTCTRL.,TRIG,,__BOOL_LITERAL(TRUE));
  __SET_VAR(data__->SVGUI_TEXTCTRL.,CODE,,__GET_VAR(data__->_TMP_CONCAT1_OUT,));
  PYTHON_EVAL_body__(&data__->SVGUI_TEXTCTRL);
  __SET_VAR(data__->,ID,,__GET_VAR(data__->SVGUI_TEXTCTRL.RESULT,));
  __SET_VAR(data__->,_TMP_AND31_OUT,,AND__BOOL__BOOL(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (UINT)2,
    (BOOL)__GET_VAR(data__->SVGUI_TEXTCTRL.ACK,),
    (BOOL)__GET_VAR(data__->SET_TEXT,)));
  __SET_VAR(data__->,_TMP_CONCAT12_OUT,,CONCAT(
    (BOOL)__BOOL_LITERAL(TRUE),
    NULL,
    (UINT)5,
    (STRING)__STRING_LITERAL(8,"setAttr("),
    (STRING)__GET_VAR(data__->ID,),
    (STRING)__STRING_LITERAL(9,",\"text\",\""),
    (STRING)__GET_VAR(data__->TEXT,),
    (STRING)__STRING_LITERAL(2,"\")")));
  __SET_VAR(data__->SETSTATE_COMMAND.,TRIG,,__GET_VAR(data__->_TMP_AND31_OUT,));
  __SET_VAR(data__->SETSTATE_COMMAND.,CODE,,__GET_VAR(data__->_TMP_CONCAT12_OUT,));
  PYTHON_EVAL_body__(&data__->SETSTATE_COMMAND);

  goto __end;

__end:
  return;
} // TEXTCTRL_body__() 





void TRAFFIC_LIGHT_SEQUENCE_init__(TRAFFIC_LIGHT_SEQUENCE *data__, BOOL retain) {
  __INIT_VAR(data__->EN,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->ENO,__BOOL_LITERAL(TRUE),retain)
  __INIT_VAR(data__->SWITCH_BUTTON,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->PEDESTRIAN_BUTTON,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->RED_LIGHT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->ORANGE_LIGHT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->GREEN_LIGHT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->PEDESTRIAN_RED_LIGHT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->PEDESTRIAN_GREEN_LIGHT,__BOOL_LITERAL(FALSE),retain)
  TON_init__(&data__->TON1,retain);
  TON_init__(&data__->TON2,retain);
  __INIT_VAR(data__->ALLOW_CARS,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->WARN_CARS,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->STOP_CARS,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->ALLOW_PEDESTRIANS,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->STOP_PEDESTRIANS,__BOOL_LITERAL(FALSE),retain)
  TON_init__(&data__->TON3,retain);
  R_TRIG_init__(&data__->R_TRIG0,retain);
  R_TRIG_init__(&data__->R_TRIG1,retain);
  SR_init__(&data__->SR0,retain);
  __INIT_VAR(data__->_TMP_NOT42_OUT,__BOOL_LITERAL(FALSE),retain)
  __INIT_VAR(data__->_TMP_OR35_OUT,__BOOL_LITERAL(FALSE),retain)
  UINT i;
  data__->__nb_steps = 6;
  static const STEP temp_step = {{0, 0}, 0, {{0, 0}, 0}};
  for(i = 0; i < data__->__nb_steps; i++) {
    data__->__step_list[i] = temp_step;
  }
  __SET_VAR(data__->,__step_list[0].X,,1);
  data__->__nb_actions = 13;
  static const ACTION temp_action = {0, {0, 0}, 0, 0, {0, 0}, {0, 0}};
  for(i = 0; i < data__->__nb_actions; i++) {
    data__->__action_list[i] = temp_action;
  }
  data__->__nb_transitions = 11;
  data__->__lasttick_time = __CURRENT_TIME;
}

// Steps definitions
#define STANDSTILL __step_list[0]
#define __SFC_STANDSTILL 0
#define ORANGE __step_list[1]
#define __SFC_ORANGE 1
#define RED __step_list[2]
#define __SFC_RED 2
#define PEDESTRIAN_GREEN __step_list[3]
#define __SFC_PEDESTRIAN_GREEN 3
#define PEDESTRIAN_RED __step_list[4]
#define __SFC_PEDESTRIAN_RED 4
#define GREEN __step_list[5]
#define __SFC_GREEN 5

// Actions definitions
#define __SFC_STANDSTILL_INLINE1 0
#define __SFC_BLINK_ORANGE_LIGHT 1
#define __SFC_COMPUTE_FUNCTION_BLOCKS 2
#define __SFC_PEDESTRIAN_RED_LIGHT 3
#define __SFC_PEDESTRIAN_GREEN_LIGHT 4
#define __SFC_RED_LIGHT 5
#define __SFC_GREEN_LIGHT 6
#define __SFC_ORANGE_LIGHT 7
#define __SFC_STOP_CARS 8
#define __SFC_ALLOW_PEDESTRIANS 9
#define __SFC_STOP_PEDESTRIANS 10
#define __SFC_ALLOW_CARS 11
#define __SFC_WARN_CARS 12

// Code part
void TRAFFIC_LIGHT_SEQUENCE_body__(TRAFFIC_LIGHT_SEQUENCE *data__) {
  // Control execution
  if (!__GET_VAR(data__->EN)) {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(FALSE));
    return;
  }
  else {
    __SET_VAR(data__->,ENO,,__BOOL_LITERAL(TRUE));
  }
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
  if (__GET_VAR(data__->STANDSTILL.X)) {
    __SET_VAR(data__->,__transition_list[0],,__GET_VAR(data__->SWITCH_BUTTON,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[0],,__GET_VAR(data__->__transition_list[0]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[0],,__GET_VAR(data__->SWITCH_BUTTON,));
    }
    __SET_VAR(data__->,__transition_list[0],,0);
  }
  if (__GET_VAR(data__->ORANGE.X)) {
    __SET_VAR(data__->,__transition_list[1],,__GET_VAR(data__->STOP_CARS,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[1],,__GET_VAR(data__->__transition_list[1]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[1],,__GET_VAR(data__->STOP_CARS,));
    }
    __SET_VAR(data__->,__transition_list[1],,0);
  }
  if (__GET_VAR(data__->RED.X)) {
    __SET_VAR(data__->,__transition_list[2],,__GET_VAR(data__->ALLOW_PEDESTRIANS,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[2],,__GET_VAR(data__->__transition_list[2]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[2],,__GET_VAR(data__->ALLOW_PEDESTRIANS,));
    }
    __SET_VAR(data__->,__transition_list[2],,0);
  }
  if (__GET_VAR(data__->PEDESTRIAN_GREEN.X)) {
    __SET_VAR(data__->,__transition_list[3],,__GET_VAR(data__->STOP_PEDESTRIANS,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[3],,__GET_VAR(data__->__transition_list[3]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[3],,__GET_VAR(data__->STOP_PEDESTRIANS,));
    }
    __SET_VAR(data__->,__transition_list[3],,0);
  }
  if (__GET_VAR(data__->PEDESTRIAN_RED.X)) {
    __SET_VAR(data__->,__transition_list[4],,__GET_VAR(data__->ALLOW_CARS,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[4],,__GET_VAR(data__->__transition_list[4]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[4],,__GET_VAR(data__->ALLOW_CARS,));
    }
    __SET_VAR(data__->,__transition_list[4],,0);
  }
  if (__GET_VAR(data__->GREEN.X)) {
    __SET_VAR(data__->,__transition_list[5],,!(__GET_VAR(data__->SWITCH_BUTTON,)));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[5],,__GET_VAR(data__->__transition_list[5]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[5],,!(__GET_VAR(data__->SWITCH_BUTTON,)));
    }
    __SET_VAR(data__->,__transition_list[5],,0);
  }
  if (__GET_VAR(data__->GREEN.X)) {
    __SET_VAR(data__->,__transition_list[6],,__GET_VAR(data__->_TMP_OR35_OUT,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[6],,__GET_VAR(data__->__transition_list[6]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[6],,__GET_VAR(data__->_TMP_OR35_OUT,));
    }
    __SET_VAR(data__->,__transition_list[6],,0);
  }
  if (__GET_VAR(data__->PEDESTRIAN_RED.X)) {
    __SET_VAR(data__->,__transition_list[7],,!(__GET_VAR(data__->SWITCH_BUTTON,)));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[7],,__GET_VAR(data__->__transition_list[7]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[7],,!(__GET_VAR(data__->SWITCH_BUTTON,)));
    }
    __SET_VAR(data__->,__transition_list[7],,0);
  }
  if (__GET_VAR(data__->PEDESTRIAN_GREEN.X)) {
    __SET_VAR(data__->,__transition_list[8],,!(__GET_VAR(data__->SWITCH_BUTTON,)));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[8],,__GET_VAR(data__->__transition_list[8]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[8],,!(__GET_VAR(data__->SWITCH_BUTTON,)));
    }
    __SET_VAR(data__->,__transition_list[8],,0);
  }
  if (__GET_VAR(data__->RED.X)) {
    __SET_VAR(data__->,__transition_list[9],,__GET_VAR(data__->_TMP_NOT42_OUT,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[9],,__GET_VAR(data__->__transition_list[9]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[9],,__GET_VAR(data__->_TMP_NOT42_OUT,));
    }
    __SET_VAR(data__->,__transition_list[9],,0);
  }
  if (__GET_VAR(data__->ORANGE.X)) {
    __SET_VAR(data__->,__transition_list[10],,__GET_VAR(data__->_TMP_NOT42_OUT,));
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[10],,__GET_VAR(data__->__transition_list[10]));
    }
  }
  else {
    if (__DEBUG) {
      __SET_VAR(data__->,__debug_transition_list[10],,__GET_VAR(data__->_TMP_NOT42_OUT,));
    }
    __SET_VAR(data__->,__transition_list[10],,0);
  }

  // Transitions reset steps
  if (__GET_VAR(data__->__transition_list[0])) {
    __SET_VAR(data__->,STANDSTILL.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[1])) {
    __SET_VAR(data__->,ORANGE.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[2])) {
    __SET_VAR(data__->,RED.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[3])) {
    __SET_VAR(data__->,PEDESTRIAN_GREEN.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[4])) {
    __SET_VAR(data__->,PEDESTRIAN_RED.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[5])) {
    __SET_VAR(data__->,GREEN.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[6])) {
    __SET_VAR(data__->,GREEN.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[7])) {
    __SET_VAR(data__->,PEDESTRIAN_RED.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[8])) {
    __SET_VAR(data__->,PEDESTRIAN_GREEN.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[9])) {
    __SET_VAR(data__->,RED.X,,0);
  }
  if (__GET_VAR(data__->__transition_list[10])) {
    __SET_VAR(data__->,ORANGE.X,,0);
  }

  // Transitions set steps
  if (__GET_VAR(data__->__transition_list[0])) {
    __SET_VAR(data__->,ORANGE.X,,1);
    data__->ORANGE.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[1])) {
    __SET_VAR(data__->,RED.X,,1);
    data__->RED.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[2])) {
    __SET_VAR(data__->,PEDESTRIAN_GREEN.X,,1);
    data__->PEDESTRIAN_GREEN.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[3])) {
    __SET_VAR(data__->,PEDESTRIAN_RED.X,,1);
    data__->PEDESTRIAN_RED.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[4])) {
    __SET_VAR(data__->,GREEN.X,,1);
    data__->GREEN.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[5])) {
    __SET_VAR(data__->,STANDSTILL.X,,1);
    data__->STANDSTILL.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[6])) {
    __SET_VAR(data__->,ORANGE.X,,1);
    data__->ORANGE.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[7])) {
    __SET_VAR(data__->,STANDSTILL.X,,1);
    data__->STANDSTILL.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[8])) {
    __SET_VAR(data__->,STANDSTILL.X,,1);
    data__->STANDSTILL.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[9])) {
    __SET_VAR(data__->,STANDSTILL.X,,1);
    data__->STANDSTILL.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }
  if (__GET_VAR(data__->__transition_list[10])) {
    __SET_VAR(data__->,STANDSTILL.X,,1);
    data__->STANDSTILL.T.value = __time_to_timespec(1, 0, 0, 0, 0, 0);
  }

  // Steps association
  // STANDSTILL action associations
  {
    char active = __GET_VAR(data__->STANDSTILL.X);
    char activated = active && !data__->STANDSTILL.prev_state;
    char desactivated = !active && data__->STANDSTILL.prev_state;

    if (activated)    {__SET_VAR(data__->,__action_list[__SFC_STANDSTILL_INLINE1].state,,1);}
    else              {__SET_VAR(data__->,__action_list[__SFC_STANDSTILL_INLINE1].state,,0);};

    if (active)       {__SET_VAR(data__->,__action_list[__SFC_BLINK_ORANGE_LIGHT].state,,1);};
    if (desactivated) {__SET_VAR(data__->,__action_list[__SFC_BLINK_ORANGE_LIGHT].state,,0);};

    if (active)       {data__->__action_list[__SFC_PEDESTRIAN_RED_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_PEDESTRIAN_GREEN_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_RED_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_GREEN_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_COMPUTE_FUNCTION_BLOCKS].set = 1;}

  }

  // ORANGE action associations
  {
    char active = __GET_VAR(data__->ORANGE.X);
    char activated = active && !data__->ORANGE.prev_state;
    char desactivated = !active && data__->ORANGE.prev_state;

    if (active)       {data__->__action_list[__SFC_GREEN_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_ORANGE_LIGHT].set = 1;}

    if (active)       {data__->__action_list[__SFC_PEDESTRIAN_RED_LIGHT].set = 1;}

    if (active && __time_cmp(data__->ORANGE.T.value, __time_to_timespec(1, 0, 2, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,STOP_CARS,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,STOP_CARS,,0);};

  }

  // RED action associations
  {
    char active = __GET_VAR(data__->RED.X);
    char activated = active && !data__->RED.prev_state;
    char desactivated = !active && data__->RED.prev_state;

    if (active)       {data__->__action_list[__SFC_ORANGE_LIGHT].reset = 1;}

    if (active)       {data__->__action_list[__SFC_RED_LIGHT].set = 1;}

    if (active && __time_cmp(data__->RED.T.value, __time_to_timespec(1, 0, 2, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,ALLOW_PEDESTRIANS,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,ALLOW_PEDESTRIANS,,0);};

  }

  // PEDESTRIAN_GREEN action associations
  {
    char active = __GET_VAR(data__->PEDESTRIAN_GREEN.X);
    char activated = active && !data__->PEDESTRIAN_GREEN.prev_state;
    char desactivated = !active && data__->PEDESTRIAN_GREEN.prev_state;

    if (active)       {data__->__action_list[__SFC_PEDESTRIAN_GREEN_LIGHT].set = 1;}

    if (active)       {data__->__action_list[__SFC_PEDESTRIAN_RED_LIGHT].reset = 1;}

    if (active && __time_cmp(data__->PEDESTRIAN_GREEN.T.value, __time_to_timespec(1, 0, 40, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,STOP_PEDESTRIANS,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,STOP_PEDESTRIANS,,0);};

  }

  // PEDESTRIAN_RED action associations
  {
    char active = __GET_VAR(data__->PEDESTRIAN_RED.X);
    char activated = active && !data__->PEDESTRIAN_RED.prev_state;
    char desactivated = !active && data__->PEDESTRIAN_RED.prev_state;

    if (active)       {data__->__action_list[__SFC_PEDESTRIAN_RED_LIGHT].set = 1;}

    if (active)       {data__->__action_list[__SFC_PEDESTRIAN_GREEN_LIGHT].reset = 1;}

    if (active && __time_cmp(data__->PEDESTRIAN_RED.T.value, __time_to_timespec(1, 0, 2, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,ALLOW_CARS,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,ALLOW_CARS,,0);};

  }

  // GREEN action associations
  {
    char active = __GET_VAR(data__->GREEN.X);
    char activated = active && !data__->GREEN.prev_state;
    char desactivated = !active && data__->GREEN.prev_state;

    if (active)       {data__->__action_list[__SFC_GREEN_LIGHT].set = 1;}

    if (active)       {data__->__action_list[__SFC_RED_LIGHT].reset = 1;}

    if (active && __time_cmp(data__->GREEN.T.value, __time_to_timespec(1, 0, 20, 0, 0, 0)) >= 0) 
                      {__SET_VAR(data__->,WARN_CARS,,1);}
    else if (desactivated)
                      {__SET_VAR(data__->,WARN_CARS,,0);};

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
  if (data__->__action_list[__SFC_PEDESTRIAN_RED_LIGHT].reset) {
    __SET_VAR(data__->,PEDESTRIAN_RED_LIGHT,,0);
  }
  else if (data__->__action_list[__SFC_PEDESTRIAN_RED_LIGHT].set) {
    __SET_VAR(data__->,PEDESTRIAN_RED_LIGHT,,1);
  }
  if (data__->__action_list[__SFC_PEDESTRIAN_GREEN_LIGHT].reset) {
    __SET_VAR(data__->,PEDESTRIAN_GREEN_LIGHT,,0);
  }
  else if (data__->__action_list[__SFC_PEDESTRIAN_GREEN_LIGHT].set) {
    __SET_VAR(data__->,PEDESTRIAN_GREEN_LIGHT,,1);
  }
  if (data__->__action_list[__SFC_RED_LIGHT].reset) {
    __SET_VAR(data__->,RED_LIGHT,,0);
  }
  else if (data__->__action_list[__SFC_RED_LIGHT].set) {
    __SET_VAR(data__->,RED_LIGHT,,1);
  }
  if (data__->__action_list[__SFC_GREEN_LIGHT].reset) {
    __SET_VAR(data__->,GREEN_LIGHT,,0);
  }
  else if (data__->__action_list[__SFC_GREEN_LIGHT].set) {
    __SET_VAR(data__->,GREEN_LIGHT,,1);
  }
  if (data__->__action_list[__SFC_ORANGE_LIGHT].reset) {
    __SET_VAR(data__->,ORANGE_LIGHT,,0);
  }
  else if (data__->__action_list[__SFC_ORANGE_LIGHT].set) {
    __SET_VAR(data__->,ORANGE_LIGHT,,1);
  }
  if (data__->__action_list[__SFC_STOP_CARS].reset) {
    __SET_VAR(data__->,STOP_CARS,,0);
  }
  else if (data__->__action_list[__SFC_STOP_CARS].set) {
    __SET_VAR(data__->,STOP_CARS,,1);
  }
  if (data__->__action_list[__SFC_ALLOW_PEDESTRIANS].reset) {
    __SET_VAR(data__->,ALLOW_PEDESTRIANS,,0);
  }
  else if (data__->__action_list[__SFC_ALLOW_PEDESTRIANS].set) {
    __SET_VAR(data__->,ALLOW_PEDESTRIANS,,1);
  }
  if (data__->__action_list[__SFC_STOP_PEDESTRIANS].reset) {
    __SET_VAR(data__->,STOP_PEDESTRIANS,,0);
  }
  else if (data__->__action_list[__SFC_STOP_PEDESTRIANS].set) {
    __SET_VAR(data__->,STOP_PEDESTRIANS,,1);
  }
  if (data__->__action_list[__SFC_ALLOW_CARS].reset) {
    __SET_VAR(data__->,ALLOW_CARS,,0);
  }
  else if (data__->__action_list[__SFC_ALLOW_CARS].set) {
    __SET_VAR(data__->,ALLOW_CARS,,1);
  }
  if (data__->__action_list[__SFC_WARN_CARS].reset) {
    __SET_VAR(data__->,WARN_CARS,,0);
  }
  else if (data__->__action_list[__SFC_WARN_CARS].set) {
    __SET_VAR(data__->,WARN_CARS,,1);
  }
  if(__GET_VAR(data__->__action_list[__SFC_STANDSTILL_INLINE1].state)) {
    __SET_VAR(data__->,ORANGE_LIGHT,,1);
  }

  if(__GET_VAR(data__->__action_list[__SFC_BLINK_ORANGE_LIGHT].state)) {
    __SET_VAR(data__->TON1.,IN,,!(__GET_VAR(data__->ORANGE_LIGHT,)));
    __SET_VAR(data__->TON1.,PT,,__time_to_timespec(1, 500, 0, 0, 0, 0));
    TON_body__(&data__->TON1);
    __SET_VAR(data__->R_TRIG1.,CLK,,__GET_VAR(data__->TON1.Q,));
    R_TRIG_body__(&data__->R_TRIG1);
    if (__GET_VAR(data__->R_TRIG1.Q,)) {
      __SET_VAR(data__->,ORANGE_LIGHT,,__BOOL_LITERAL(TRUE));
    };
    __SET_VAR(data__->TON2.,IN,,__GET_VAR(data__->ORANGE_LIGHT,));
    __SET_VAR(data__->TON2.,PT,,__time_to_timespec(1, 500, 0, 0, 0, 0));
    TON_body__(&data__->TON2);
    __SET_VAR(data__->R_TRIG0.,CLK,,__GET_VAR(data__->TON2.Q,));
    R_TRIG_body__(&data__->R_TRIG0);
    if (__GET_VAR(data__->R_TRIG0.Q,)) {
      __SET_VAR(data__->,ORANGE_LIGHT,,__BOOL_LITERAL(FALSE));
    };
  }

  if(__GET_VAR(data__->__action_list[__SFC_COMPUTE_FUNCTION_BLOCKS].state)) {
    __SET_VAR(data__->,_TMP_NOT42_OUT,,!(__GET_VAR(data__->SWITCH_BUTTON,)));
    __SET_VAR(data__->SR0.,S1,,__GET_VAR(data__->PEDESTRIAN_BUTTON,));
    __SET_VAR(data__->SR0.,R,,__GET_VAR(data__->TON3.Q,));
    SR_body__(&data__->SR0);
    __SET_VAR(data__->TON3.,IN,,__GET_VAR(data__->SR0.Q1,));
    __SET_VAR(data__->TON3.,PT,,__time_to_timespec(1, 0, 2, 0, 0, 0));
    TON_body__(&data__->TON3);
    __SET_VAR(data__->,_TMP_OR35_OUT,,OR__BOOL__BOOL(
      (BOOL)__BOOL_LITERAL(TRUE),
      NULL,
      (UINT)2,
      (BOOL)__GET_VAR(data__->TON3.Q,),
      (BOOL)__GET_VAR(data__->WARN_CARS,)));
  }



  goto __end;

__end:
  return;
} // TRAFFIC_LIGHT_SEQUENCE_body__() 

// Steps undefinitions
#undef STANDSTILL
#undef __SFC_STANDSTILL
#undef ORANGE
#undef __SFC_ORANGE
#undef RED
#undef __SFC_RED
#undef PEDESTRIAN_GREEN
#undef __SFC_PEDESTRIAN_GREEN
#undef PEDESTRIAN_RED
#undef __SFC_PEDESTRIAN_RED
#undef GREEN
#undef __SFC_GREEN

// Actions undefinitions
#undef __SFC_STANDSTILL_INLINE1
#undef __SFC_BLINK_ORANGE_LIGHT
#undef __SFC_COMPUTE_FUNCTION_BLOCKS
#undef __SFC_PEDESTRIAN_RED_LIGHT
#undef __SFC_PEDESTRIAN_GREEN_LIGHT
#undef __SFC_RED_LIGHT
#undef __SFC_GREEN_LIGHT
#undef __SFC_ORANGE_LIGHT
#undef __SFC_STOP_CARS
#undef __SFC_ALLOW_PEDESTRIANS
#undef __SFC_STOP_PEDESTRIANS
#undef __SFC_ALLOW_CARS
#undef __SFC_WARN_CARS





void MAIN_PROGRAM_init__(MAIN_PROGRAM *data__, BOOL retain) {
  TRAFFIC_LIGHT_SEQUENCE_init__(&data__->TRAFIC_LIGHT_SEQUENCE0,retain);
  BUTTON_init__(&data__->SWITCHBUTTON,retain);
  BUTTON_init__(&data__->PEDESTRIANBUTTON,retain);
  LED_init__(&data__->REDLIGHT,retain);
  LED_init__(&data__->ORANGELIGHT,retain);
  LED_init__(&data__->GREENLIGHT,retain);
  LED_init__(&data__->PEDESTRIANREDLIGHT,retain);
  LED_init__(&data__->PEDESTRIANGREENLIGHT,retain);
}

// Code part
void MAIN_PROGRAM_body__(MAIN_PROGRAM *data__) {
  // Initialise TEMP variables

  __SET_VAR(data__->SWITCHBUTTON.,BACK_ID,,__STRING_LITERAL(10,"SWITCH_OFF"));
  __SET_VAR(data__->SWITCHBUTTON.,SELE_ID,,__STRING_LITERAL(9,"SWITCH_ON"));
  __SET_VAR(data__->SWITCHBUTTON.,TOGGLE,,1);
  BUTTON_body__(&data__->SWITCHBUTTON);
  __SET_VAR(data__->PEDESTRIANBUTTON.,BACK_ID,,__STRING_LITERAL(14,"PEDESTRIAN_OFF"));
  __SET_VAR(data__->PEDESTRIANBUTTON.,SELE_ID,,__STRING_LITERAL(13,"PEDESTRIAN_ON"));
  BUTTON_body__(&data__->PEDESTRIANBUTTON);
  __SET_VAR(data__->TRAFIC_LIGHT_SEQUENCE0.,SWITCH_BUTTON,,__GET_VAR(data__->SWITCHBUTTON.STATE_OUT,));
  __SET_VAR(data__->TRAFIC_LIGHT_SEQUENCE0.,PEDESTRIAN_BUTTON,,__GET_VAR(data__->PEDESTRIANBUTTON.STATE_OUT,));
  TRAFFIC_LIGHT_SEQUENCE_body__(&data__->TRAFIC_LIGHT_SEQUENCE0);
  __SET_VAR(data__->REDLIGHT.,BACK_ID,,__STRING_LITERAL(7,"RED_OFF"));
  __SET_VAR(data__->REDLIGHT.,SELE_ID,,__STRING_LITERAL(6,"RED_ON"));
  __SET_VAR(data__->REDLIGHT.,STATE_IN,,__GET_VAR(data__->TRAFIC_LIGHT_SEQUENCE0.RED_LIGHT,));
  LED_body__(&data__->REDLIGHT);
  __SET_VAR(data__->ORANGELIGHT.,BACK_ID,,__STRING_LITERAL(10,"ORANGE_OFF"));
  __SET_VAR(data__->ORANGELIGHT.,SELE_ID,,__STRING_LITERAL(9,"ORANGE_ON"));
  __SET_VAR(data__->ORANGELIGHT.,STATE_IN,,__GET_VAR(data__->TRAFIC_LIGHT_SEQUENCE0.ORANGE_LIGHT,));
  LED_body__(&data__->ORANGELIGHT);
  __SET_VAR(data__->GREENLIGHT.,BACK_ID,,__STRING_LITERAL(9,"GREEN_OFF"));
  __SET_VAR(data__->GREENLIGHT.,SELE_ID,,__STRING_LITERAL(8,"GREEN_ON"));
  __SET_VAR(data__->GREENLIGHT.,STATE_IN,,__GET_VAR(data__->TRAFIC_LIGHT_SEQUENCE0.GREEN_LIGHT,));
  LED_body__(&data__->GREENLIGHT);
  __SET_VAR(data__->PEDESTRIANREDLIGHT.,BACK_ID,,__STRING_LITERAL(18,"PEDESTRIAN_RED_OFF"));
  __SET_VAR(data__->PEDESTRIANREDLIGHT.,SELE_ID,,__STRING_LITERAL(17,"PEDESTRIAN_RED_ON"));
  __SET_VAR(data__->PEDESTRIANREDLIGHT.,STATE_IN,,__GET_VAR(data__->TRAFIC_LIGHT_SEQUENCE0.PEDESTRIAN_RED_LIGHT,));
  LED_body__(&data__->PEDESTRIANREDLIGHT);
  __SET_VAR(data__->PEDESTRIANGREENLIGHT.,BACK_ID,,__STRING_LITERAL(20,"PEDESTRIAN_GREEN_OFF"));
  __SET_VAR(data__->PEDESTRIANGREENLIGHT.,SELE_ID,,__STRING_LITERAL(19,"PEDESTRIAN_GREEN_ON"));
  __SET_VAR(data__->PEDESTRIANGREENLIGHT.,STATE_IN,,__GET_VAR(data__->TRAFIC_LIGHT_SEQUENCE0.PEDESTRIAN_GREEN_LIGHT,));
  LED_body__(&data__->PEDESTRIANGREENLIGHT);

  goto __end;

__end:
  return;
} // MAIN_PROGRAM_body__() 





