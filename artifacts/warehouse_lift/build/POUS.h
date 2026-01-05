#include "beremiz.h"
#ifndef __POUS_H
#define __POUS_H

#include "accessor.h"
#include "iec_std_lib.h"

__DECLARE_ENUMERATED_TYPE(LOGLEVEL,
  LOGLEVEL__CRITICAL,
  LOGLEVEL__WARNING,
  LOGLEVEL__INFO,
  LOGLEVEL__DEBUG
)
// FUNCTION_BLOCK LOGGER
// Data part
typedef struct {
  // FB Interface - IN, OUT, IN_OUT variables
  __DECLARE_VAR(BOOL,EN)
  __DECLARE_VAR(BOOL,ENO)
  __DECLARE_VAR(BOOL,TRIG)
  __DECLARE_VAR(STRING,MSG)
  __DECLARE_VAR(LOGLEVEL,LEVEL)

  // FB private variables - TEMP, private and located variables
  __DECLARE_VAR(BOOL,TRIG0)

} LOGGER;

void LOGGER_init__(LOGGER *data__, BOOL retain);
// Code part
void LOGGER_body__(LOGGER *data__);
// PROGRAM LIFT
// Data part
typedef struct {
  // PROGRAM Interface - IN, OUT, IN_OUT variables

  // PROGRAM private variables - TEMP, private and located variables
  __DECLARE_VAR(SINT,ASSIGNED_PALLET_RACK)
  __DECLARE_VAR(BOOL,LIFT_UP_MOTOR)
  __DECLARE_VAR(BOOL,LIFT_DOWN_MOTOR)
  __DECLARE_VAR(BOOL,CONVEYOR_MOTOR)
  __DECLARE_VAR(SINT,CURRENT_RACK)
  __DECLARE_VAR(SINT,INITIAL_RACK)
  TON TON0;
  TON TON1;
  __DECLARE_VAR(BOOL,_TMP_GT5_OUT)
  __DECLARE_VAR(BOOL,_TMP_EQ12_OUT)
  __DECLARE_VAR(BOOL,_TMP_EQ23_OUT)
  STEP __step_list[5];
  UINT __nb_steps;
  ACTION __action_list[4];
  UINT __nb_actions;
  __IEC_BOOL_t __transition_list[5];
  __IEC_BOOL_t __debug_transition_list[5];
  UINT __nb_transitions;
  TIME __lasttick_time;

} LIFT;

void LIFT_init__(LIFT *data__, BOOL retain);
// Code part
void LIFT_body__(LIFT *data__);
#endif //__POUS_H
