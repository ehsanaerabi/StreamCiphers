/* This program is used to generate the first 256 keystream bytes of stream cipher HC-128 for a 128-bit key and a 128-bit IV

   HC-128 is a final portfolio cipher of eSTREAM, of the European Network of 
   Excellence for Cryptology (ECRYPT, 2004-2008). 
   The docuement of HC-128 is available at:
   1) Hongjun Wu. ``The Stream Cipher HC-128.'' New Stream Cipher Designs -- The eSTREAM Finalists, LNCS 4986, pp. 39-47, Springer-Verlag, 2008.  
   2) eSTREAM website:  http://www.ecrypt.eu.org/stream/hcp3.html

   -----------------------------------
   Written by: Hongjun Wu
   Last Modified: December 15, 2009
*/


#include <stdio.h>
#include "hc128_ref.h"
//#include "hc128_opt32.h"

int main() 
{
      unsigned char key[16],iv[16];
      unsigned char message[1024],ciphertext[1024];
      unsigned long long msglength;

      unsigned long i;

      /*set the value of the key and iv*/
      for (i = 0; i < 16; i++) {
            key[i] = 0;
            iv[i] = 0;
      }
      /*key[0] = 0x55;*/
      /*iv[0] = 1;*/

      /*set the value of message to 0 so that the ciphertext contains the keystream*/ 
      for (i = 0; i < 1024; i++) message[i] = 0;

      /*generate the first 256 keystream bytes*/
      msglength = 256;

      HC128(key,iv,message,ciphertext,msglength);

      /*print out the first 256 keystream bytes*/
      printf("The first %d keystream bytes are: \n\n",msglength);
      for (i = 0; i < msglength; i++) {
            printf("%x%x",ciphertext[i] >> 4, ciphertext[i] & 0xf);
            if ( ((i+1)%16) == 0 ) printf("\n");
      } 
      printf("\n");
    
      return (0);
}


