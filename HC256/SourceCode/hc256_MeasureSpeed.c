/* This program is used to measure the encryption speed of stream cipher HC-256 for a 256-bit key and a 256-bit IV
  
   The document of HC-256 is available at:
   1) Hongjun Wu. ``A New Stream Cipher HC-256.'' Fast Software Encryption -- FSE 2004, LNCS 3017, pp. 226-244, Springer-Verlag 2004.
   2) eSTREAM website:  http://www.ecrypt.eu.org/stream/hcp3.html

   -----------------------------------
   The encryption speed is measured by repeatedly encrypting a 64-byte buffer.

   -----------------------------------
   Written by: Hongjun Wu
   Last Modified: December 15, 2009
*/


#include "hc256_opt32.h"
//#include "hc256_ref.h"

int main() 
{
      unsigned char key[32],iv[32];
      unsigned char message[128],ciphertext[128];
      unsigned long long msglength;
      HC256_State state;

      unsigned long i;
    
   

      /*set the value of the key and iv*/
      for (i = 0; i < 32; i++) {key[i] = 0; iv[i] = 0;}
      /*key[0] = 0x55;*/

      /*initialize the message*/
      for (i = 0; i < 128; i++) message[i] = 0;

      /*key and iv setup*/
      Initialization(&state,key,iv);

      /*mesure the encryption speed by encrypting a 64-byte message repeatedly for 2*0x4000000 times*/
      
      msglength = 128;


	//while(1)
      EncryptMessage(&state,message,ciphertext,msglength);


      return (0);
}

