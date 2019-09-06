/* This program is used to measure the encryption speed of stream cipher HC-128 for a 128-bit key and a 128-bit IV
  
   HC-128 is a final portfolio cipher of eSTREAM, of the European Network of 
   Excellence for Cryptology (ECRYPT, 2004-2008). 
   The docuement of HC-128 is available at:
   1) Hongjun Wu. ``The Stream Cipher HC-128.'' New Stream Cipher Designs -- The eSTREAM Finalists, LNCS 4986, pp. 39-47, Springer-Verlag, 2008.  
   2) eSTREAM website:  http://www.ecrypt.eu.org/stream/hcp3.html

   -----------------------------------
   The encryption speed is measured by repeatedly encrypting a 64-byte buffer.

   -----------------------------------
   Written by: Hongjun Wu
   Last Modified: December 15, 2009
*/

//#include <stdio.h>
//#include <time.h>

#include "hc128_opt32.h"
//#include "hc128_ref.h"

int main(void) 
{
      unsigned char key[16],iv[16];
      unsigned char message[128],ciphertext[128];
      unsigned long long msglength;
      HC128_State state;

      unsigned long i;
    
   //   clock_t start, finish;
    //  double duration, speed;
   

      /*set the value of the key and iv*/
      for (i = 0; i < 16; i++) {key[i] = 0; iv[i] = 0;}
      /*key[0] = 0x55;*/

      /*initialize the message*/
      for (i = 0; i < 128; i++) message[i] = 0;

      /*key and iv setup*/
      Initialization(&state,key,iv);

      /*mesure the encryption speed by encrypting a 64-byte message repeatedly for 2*0x4000000 times*/

      msglength = 128;

 
	//while(1)
    EncryptMessage(&state,message,ciphertext,msglength);

//printf("OK");
      return (0);
}

