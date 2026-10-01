/*******************************************************************************
* Title: Oven
* variables: time, temperature
* Date: 9/7/2021
* Author: Bonnie

* 
* Brief
* =====
* This is an example firmware for our Arduino compatible reflow oven controller. 
* The reflow curve used in this firmware is meant for lead-free profile 
* (it's even easier for leaded process!). You'll need to use the MAX31855 
* library for Arduino if you are having a shield of v1.60 & above which can be 
* downloaded from our GitHub repository. Please check our wiki 
* (www.rocketscream.com/wiki) for more information on using this piece of code 
* together with the reflow oven controller shield. 
*
* Temperature (Degree Celcius)                 Magic Happens Here!
* 245-|                                               x  x  
*     |                                            x        x
*     |                                         x              x
*     |                                      x                    x
* 200-|                                   x                          x
*     |                              x    |                          |   x   
*     |                         x         |                          |       x
*     |                    x              |                          |
* 150-|               x                   |                          |
*     |             x |                   |                          |
*     |           x   |                   |                          | 
*     |         x     |                   |                          | 
*     |       x       |                   |                          | 
*     |     x         |                   |                          |
*     |   x           |                   |                          |
* 30 -| x             |                   |                          |
*     |<  60 - 90 s  >|<    90 - 120 s   >|<       90 - 120 s       >|
*     | Preheat Stage |   Soaking Stage   |       Reflow Stage       | Cool
*  0  |_ _ _ _ _ _ _ _|_ _ _ _ _ _ _ _ _ _|_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
*                                                                Time (Seconds)
*
* This firmware owed very much on the works of other talented individuals as
* follows:
* ==========================================
* Brett Beauregard (www.brettbeauregard.com)
* ==========================================
* Author of Arduino PID library. On top of providing industry standard PID 
* implementation, he gave a lot of help in making this reflow oven controller 
* possible using his awesome library.
*
* ==========================================
* Limor Fried of Adafruit (www.adafruit.com)
* ==========================================
* Author of Arduino MAX6675 library. Adafruit has been the source of tonnes of
* tutorials, examples, and libraries for everyone to learn.
*
* Disclaimer
* ==========
* Dealing with high voltage is a very dangerous act! Please make sure you know
* what you are dealing with and have proper knowledge before hand. Your use of 
* any information or materials on this reflow oven controller is entirely at 
* your own risk, for which we shall not be liable. 
*
* Licences
* ========
* This reflow oven controller hardware and firmware are released under the 
* Creative Commons Share Alike v3.0 license
* http://creativecommons.org/licenses/by-sa/3.0/ 
* You are free to take this piece of code, use it and modify it. 
* All we ask is attribution including the supporting libraries used in this 
* firmware. 
*
* Required Libraries
* ==================
* - Arduino PID Library: 
*   >> https://github.com/br3ttb/Arduino-PID-Library
* - MAX31855 Library (for board v1.60 & above): 
*   >> https://github.com/rocketscream/MAX31855
* - MAX6675 Library (for board v1.50 & below):
*   >> https://github.com/adafruit/MAX6675-library
*/

// Comment either one the following #define to select your board revision
// Newer board version starts from v1.60 using MAX31855KASA+ chip 
#define  USE_MAX31855
// Older board version below version v1.60 using MAX6675ISA+ chip
//#define USE_MAX6675

// ***** INCLUDES *****
#ifdef	USE_MAX31855
  #include <MAX31855.h>
#else
	#include <max6675.h>
#endif

// ***** TYPE DEFINITIONS *****
typedef enum OVEN_STATE
{
  O_IDLE,
  O_PREHEAT,
  O_COOK,
  O_COOL,
  O_COMPLETE,
	O_TOO_HOT,
  O_ERROR
} ovenState_t;

typedef enum OVEN_STATUS
{
  O_OFF,
  O_ON
} ovenStatus_t;

typedef	enum SWITCH
{
	SWITCH_NONE,
	SWITCH_1,	
	SWITCH_2
}	switch_t;

typedef enum DEBOUNCE_STATE
{
  DEBOUNCE_STATE_IDLE,
  DEBOUNCE_STATE_CHECK,
  DEBOUNCE_STATE_RELEASE
} debounceState_t;

// ***** CONSTANTS *****
#define TEMPERATURE_ROOM 50
#define TEMPERATURE_COOK 150
#define COOK_TIME 9000
#define SENSOR_SAMPLING_TIME 1000
#define DEBOUNCE_PERIOD_MIN 50


// ***** PIN ASSIGNMENT *****
#ifdef	USE_MAX31855
	int ssrPin = 5;
	int thermocoupleSOPin = A3;
	int thermocoupleCSPin = A2;
	int thermocoupleCLKPin = A1;
	int ledRedPin = 4;
#else
	int ssrPin = 5;
	int thermocoupleSOPin = A5;
	int thermocoupleCSPin = A4;
	int thermocoupleCLKPin = A3;
	int lcdRsPin = 7;
	int lcdEPin = 8;
	int lcdD4Pin = 9;
	int lcdD5Pin = 10;
	int lcdD6Pin = 11;
	int lcdD7Pin = 12;
	int ledRedPin = A1;
	int ledGreenPin = A0;
	int buzzerPin = 6;
	int switch1Pin = 2;
	int switch2Pin = 3;
#endif

// ***** PID CONTROL VARIABLES *****
double input;
double output;
unsigned long nextCheck;
unsigned long nextRead;
// Reflow oven controller state machine state variable
ovenState_t ovenState;
// Reflow oven controller status
ovenStatus_t ovenStatus;
// Switch debounce state machine state variable
// debounceState_t debounceState;
// // Switch debounce timer
// long lastDebounceTime;
// // Switch press status
// switch_t switchStatus;
// Seconds timer
int timerSeconds;
int cookstart;

#ifdef	USE_MAX31855
	MAX31855 thermocouple(thermocoupleSOPin, thermocoupleCSPin, 
												thermocoupleCLKPin);
#else
	MAX6675 thermocouple(thermocoupleCLKPin, thermocoupleCSPin, 
											 thermocoupleSOPin);
#endif

void setup()
{
  // SSR pin initialization to ensure reflow oven is off
  digitalWrite(ssrPin, LOW);
  pinMode(ssrPin, OUTPUT);

  // Buzzer pin initialization to ensure annoying buzzer is off
  // digitalWrite(buzzerPin, LOW);
  // pinMode(buzzerPin, OUTPUT);

  // LED pins initialization and turn on upon start-up (active low)
  digitalWrite(ledRedPin, LOW);
  pinMode(ledRedPin, OUTPUT);
	#ifdef USE_MAX6675
    // LED pins initialization and turn on upon start-up (active low)
    digitalWrite(ledGreenPin, LOW);	
    pinMode(ledGreenPin, OUTPUT);
    // Switch pins initialization
    pinMode(switch1Pin, INPUT);
    pinMode(switch2Pin, INPUT);
	#endif	

  // Start-up splash
  // digitalWrite(buzzerPin, HIGH);

  // digitalWrite(buzzerPin, LOW);
  delay(2500);


  // Serial communication at 57600 bps
  Serial.begin(57600);

  // Turn off LED (active low)
  digitalWrite(ledRedPin, HIGH);
	#ifdef  USE_MAX6675
		digitalWrite(ledGreenPin, HIGH);
	#endif

  // Initialize time keeping variable
  nextCheck = millis();
  // Initialize thermocouple reading variable
  nextRead = millis();
}

void loop()
{
  // Current time
  unsigned long now;

  // Time to read thermocouple?
  if (millis() > nextRead)
  {
    // Read thermocouple next sampling period
    nextRead += SENSOR_SAMPLING_TIME;
    // Read current temperature
    #ifdef	USE_MAX31855
        input = thermocouple.readThermocouple(CELSIUS);
    #else
        input = thermocouple.readCelsius();
    #endif
		
    // If thermocouple problem detected
    #ifdef	USE_MAX6675
        if (isnan(input))
    #else
        if((input == FAULT_OPEN) || (input == FAULT_SHORT_GND) ||
             (input == FAULT_SHORT_VCC))
    #endif
		{
    // Illegal operation
    ovenState = O_ERROR;
    ovenStatus = O_OFF;
    }
  }

  if (millis() > nextCheck)
  {
    // Check input in the next seconds
    nextCheck += 1000;
    // If reflow process is on going
    if (ovenStatus == O_ON)
    {
      // Toggle red LED as system heart beat
      digitalWrite(ledRedPin, !(digitalRead(ledRedPin)));
      // Increase seconds timer for reflow curve analysis
      timerSeconds++;
      // Send temperature and time stamp to serial 
      Serial.print(timerSeconds);
      Serial.print(" ");
      Serial.print(input);
      Serial.print(" ");
      Serial.println(output);
    }
    else
    {
      // Turn off red LED
      digitalWrite(ledRedPin, HIGH);
    }

    // If currently in error state
    if (ovenState == O_ERROR)
    {
      // Make sure oven is off
      ovenStatus = O_OFF;
    }

  }

  // oven state machine
  switch (ovenState)
  {
  case O_IDLE:
    // If oven temperature is still above room temperature
    if (input >= TEMPERATURE_ROOM)
    {
        ovenState = O_TOO_HOT;
    }
    else
    {
      // Send header for CSV file
      Serial.println("Time Setpoint Input Output");
      // Intialize seconds timer for serial debug information
      timerSeconds = 0;
      // Proceed to preheat stage
      ovenState = O_PREHEAT;
      
    }
    break;

  case O_PREHEAT:
    ovenStatus = O_ON;
    // If minimum soak temperature is achieve       
    if (input >= TEMPERATURE_COOK)
    {
      cookstart = millis();
      ovenState = O_COOK; 
    }
    break;

  case O_COOK:     
    // If micro soak temperature is achieved       
    if (millis() > cookstart + COOK_TIME)
    {
      ovenState = O_COOL;
    }
    else
    {
      if (ovenStatus == O_ON)
      {
        if (input > TEMPERATURE_COOK + 20)
        {
          ovenStatus = O_OFF;
        }
      }
      else if (ovenStatus == O_OFF)
      {
        if (input < TEMPERATURE_COOK)
        {
          ovenStatus = O_ON;
        }
      }
      
    }
    break; 

  case O_COOL:
    // If minimum cool temperature is achieve       
    if (input <= TEMPERATURE_ROOM)
    {
      // Turn on buzzer and green LED to indicate completion
      #ifdef	USE_MAX6675
          digitalWrite(ledGreenPin, LOW);
      #endif
      // digitalWrite(buzzerPin, HIGH);
      // Turn off reflow process
      ovenStatus = O_OFF;                
      // Proceed to reflow Completion state
      ovenState = O_COMPLETE; 
    }         
    break;    

  case O_COMPLETE:
    digitalWrite(ledRedPin, LOW);
    break;
	
    case O_TOO_HOT:
      // If oven temperature drops below room temperature
      if (input < TEMPERATURE_ROOM)
      {
          // Ready to reflow
          ovenState = O_IDLE;
      }
      break;
		
  case O_ERROR:
    // If thermocouple problem is still present
    #ifdef	USE_MAX6675
        if (isnan(input))
    #else
        if((input == FAULT_OPEN) || (input == FAULT_SHORT_GND) ||
             (input == FAULT_SHORT_VCC))
    #endif
    {
      // Wait until thermocouple wire is connected
      ovenState = O_ERROR; 
    }
    else
    {
      // Clear to perform reflow process
      ovenState = O_IDLE; 
    }
    break;    
  }    
/*
  // If switch 1 is pressed
  if (switchStatus == SWITCH_1)
  {
    // If currently reflow process is on going
    if (ovenStatus == REFLOW_STATUS_ON)
    {
      // Button press is for cancelling
      // Turn off reflow process
      ovenStatus = REFLOW_STATUS_OFF;
      // Reinitialize state machine
      ovenState = O_IDLE;
    }
  } 

  // Simple switch debounce state machine (for switch #1 (both analog & digital
	// switch supported))
  switch (debounceState)
  {
  case DEBOUNCE_STATE_IDLE:
    // No valid switch press
    switchStatus = SWITCH_NONE;
    // If switch #1 is pressed
		#ifdef	USE_MAX6675
			if (digitalRead(switch1Pin) == LOW)
		#else
			if (analogRead(switchPin) == 0)
		#endif
			{
				// Intialize debounce counter
				lastDebounceTime = millis();
				// Proceed to check validity of button press
				debounceState = DEBOUNCE_STATE_CHECK;
			}	
    break;

  case DEBOUNCE_STATE_CHECK:
		#ifdef	USE_MAX6675
			// If switch #1 is still pressed
			if (digitalRead(switch1Pin) == LOW)         //digitalRead
		#else
			if (analogRead(switchPin) == 0)
		#endif
			{
				// If minimum debounce period is completed
				if ((millis() - lastDebounceTime) > DEBOUNCE_PERIOD_MIN)
				{
					// Proceed to wait for button release
					debounceState = DEBOUNCE_STATE_RELEASE;
				}
			}
			// False trigger
			else
			{
				// Reinitialize button debounce state machine
				debounceState = DEBOUNCE_STATE_IDLE; 
			}
    break;

  case DEBOUNCE_STATE_RELEASE:
		#ifdef	USE_MAX6675	
			if (digitalRead(switch1Pin) == HIGH)
    #else
			if (analogRead(switchPin) > 0)
		#endif
		{
      // Valid switch 1 press
      switchStatus = SWITCH_1;
      // Reinitialize button debounce state machine
      debounceState = DEBOUNCE_STATE_IDLE; 
    }
    break;
  }
  */

  // PID computation and SSR control
  if (ovenStatus == O_ON)
  {
    digitalWrite(ssrPin, HIGH);   
  }
  else 
  {
    digitalWrite(ssrPin, LOW);
  }
}
