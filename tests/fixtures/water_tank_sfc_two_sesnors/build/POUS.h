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
// PROGRAM WATER_TANK_SFC
// Data part
typedef struct {
  // PROGRAM Interface - IN, OUT, IN_OUT variables

  // PROGRAM private variables - TEMP, private and located variables
  __DECLARE_VAR(BOOL,LOW_LEVEL_SENSOR)
  __DECLARE_VAR(BOOL,HIGH_LEVEL_SENSOR)
  __DECLARE_VAR(BOOL,PUMP)
  STEP __step_list[3];
  UINT __nb_steps;
  ACTION __action_list[1];
  UINT __nb_actions;
  __IEC_BOOL_t __transition_list[3];
  __IEC_BOOL_t __debug_transition_list[3];
  UINT __nb_transitions;
  TIME __lasttick_time;

} WATER_TANK_SFC;

void WATER_TANK_SFC_init__(WATER_TANK_SFC *data__, BOOL retain);
// Code part
void WATER_TANK_SFC_body__(WATER_TANK_SFC *data__);
#endif //__POUS_H
