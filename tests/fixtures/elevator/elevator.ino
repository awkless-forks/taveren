/*

 *************************************************************
 Arduino Basic Elevator Simulation 

 www.ulasdikme.com

 **********************************************************
 */








int i=1; // the value represents where elevator stay ( fisrt time elevator start in the first floor
int btn4=8; // represents the 4 th floor
int btn3=7;  //             2 nd floor
int btn2=6; //                3 th floor
int btn1=5;  //               1 st floor 

int buttonState=0;
int buttonState2=0;
int buttonState3=0;
int buttonState4=0;


int motorPin1 = 10; 
int motorPin2 = 11; 
int motorPin3 = 12; 
int motorPin4 = 13;





void setup() {

    pinMode(motorPin1, OUTPUT); 
    pinMode(motorPin2, OUTPUT); 
    pinMode(motorPin3, OUTPUT); 
    pinMode(motorPin4, OUTPUT); 
    int delayTime = 50; 


    Serial.begin(9600);

    pinMode(btn4,INPUT);
    pinMode(btn2,INPUT);
    pinMode(btn3,INPUT);
    pinMode(btn1,INPUT);


}

void loop() {
    // Serial.println("You are on the i st floor"); 
    buttonState = digitalRead(btn1);
    buttonState2 = digitalRead(btn2);
    buttonState3 = digitalRead(btn3);
    buttonState4 = digitalRead(btn4);

    /*------------------------------------------------------------------*/
    // 4 th floor required codes
    if(buttonState4 == HIGH){
        while(i<4){   
            i++;
            up();

            Serial.print("You are on the ");
            Serial.print(i);
            Serial.println("floor");


        }
        i=4;

    }// end of the buttonState4
     //------ end of the 4th floor ------
    /*------------------------------------------------------------------*/



    /*------------------------------------------------------------------*/
    //start of the 3 td floor codes ----
    if(buttonState3==HIGH){

        if(i>3){
            while(i>3) {
                i--;
                down();
                Serial.print("You are on the ");
                Serial.print(i);
                Serial.println("floor");

            }
        }
        if(i<3){ // person is waiting on the first or second floor. Call the elevater
            while(i<3){
                i++;
                up();
                Serial.print("You are on the ");
                Serial.print(i);
                Serial.println("floor");

            }

        }    


        i=3; //assign the elevator value to the three




    } // end of the buttonState3
      //end of the 3 td floor codes ---- 
    /*------------------------------------------------------------------*/ 





    /*------------------------------------------------------------------*/ 
    // 2 nd floor required codes
    if(buttonState2 == HIGH){
        if(i>2){
            while(i>2)
            {
                i--;
                down();
                Serial.print("You are on the ");
                Serial.print(i);
                Serial.println("floor");

            }  
            i=2;   
        }
        if(i<2){
            while(i<2){
                i++;
                up();
                Serial.print("You are on the ");
                Serial.print(i);
                Serial.println("floor");
            }
            i=2;
        }

    }// end of the buttonState2
     // --- end of the 2 th floor codes ---
    /*------------------------------------------------------------------*/



    /*------------------------------------------------------------------*/
    // start of the 1 st floor codes ------
    if(buttonState == HIGH){
        if(i>1){
            while(i>1){

                i--;
                down();
                Serial.print("You are on the ");
                Serial.print(i);
                Serial.println("floor");

            }
        }
        i=1;       
    }// end of the buttonState1
     //--- end of the first floor codes-----
    /*------------------------------------------------------------------*/



} 




// ------- up function which is for to go up elevator
void up() { // each floor distance where it works to up

    for(int b=0; b<300; b++){

        digitalWrite(motorPin1, LOW);
        digitalWrite(motorPin2, LOW);
        digitalWrite(motorPin3, LOW);
        digitalWrite(motorPin4, HIGH);
        delay(3);
        digitalWrite(motorPin1, LOW);
        digitalWrite(motorPin2, LOW);
        digitalWrite(motorPin3, HIGH);
        digitalWrite(motorPin4, LOW);
        delay(3);
        digitalWrite(motorPin1, LOW);
        digitalWrite(motorPin2, HIGH);
        digitalWrite(motorPin3, LOW);
        digitalWrite(motorPin4, LOW);
        delay(3);
        digitalWrite(motorPin1, HIGH);
        digitalWrite(motorPin2, LOW);
        digitalWrite(motorPin3, LOW);
        digitalWrite(motorPin4, LOW);  
        delay(3);
    }

}

void down() { // each floor distance where it works to down


    for(int a=0;a<300;a++){

        digitalWrite(motorPin1, HIGH); 
        digitalWrite(motorPin2, LOW); 
        digitalWrite(motorPin3, LOW); 
        digitalWrite(motorPin4, LOW); 
        delay(3);
        digitalWrite(motorPin1, LOW); 
        digitalWrite(motorPin2, HIGH); 
        digitalWrite(motorPin3, LOW); 
        digitalWrite(motorPin4, LOW); 
        delay(3);
        digitalWrite(motorPin1, LOW); 
        digitalWrite(motorPin2, LOW); 
        digitalWrite(motorPin3, HIGH); 
        digitalWrite(motorPin4, LOW); 
        delay(3);
        digitalWrite(motorPin1, LOW); 
        digitalWrite(motorPin2, LOW); 
        digitalWrite(motorPin3, LOW); 
        digitalWrite(motorPin4, HIGH); 
        delay(3);

    }
}
