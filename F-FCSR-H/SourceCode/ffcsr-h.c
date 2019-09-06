    /*
     * F-FCSR-H reference implementation.
     *
     * (c) 2005 FCSR project. This software is provided 'as-is', without
     * any express or implied warranty. In no event will the authors be held
     * liable for any damages arising from the use of this software.
     *
     * Permission is granted to anyone to use this software for any purpose,
     * including commercial applications, and to alter it and redistribute it
     * freely, subject to no restriction.
     *
     * Technical remarks and questions can be addressed to
     * <cedric.lauradoux@inria.fr>
     */

#include "ffcsrh-sync.h"
//#ifdef FFCSRH_EVALUATE
#include <time.h>
#include <stdlib.h>
//#endif



void ECRYPT_keysetup(
  ECRYPT_ctx* ctx, 
  const u8* key, 
  u32 keyse,                /* Key se in bits. */ 
  u32 ivse)                 /* IV se in bits. */ 
{
	u32 i;
	

	ctx->filter[0]=d0;
	ctx->filter[1]=d1;
	ctx->filter[2]=d2;
	ctx->filter[3]=d3;
	ctx->filter[4]=d4;
	
	ctx->state[0] = key[9] | key[8]<<8 | key[7]<<16 | key[6]<<24;
	ctx->state[1] = key[5] | key[4]<<8 | key[3]<<16 | key[2]<<24;
	ctx->state[2] = key[1] | key[0]<<8 | 0x00<<16 | 0x00<<24;
	ctx->state[3] = 0x00000000;
	ctx->state[4] = 0x00000000;
	
	ctx->init[0]=ctx->state[0]; 
	ctx->init[1]=ctx->state[1]; 
	ctx->init[2]=ctx->state[2]; 
}

void ECRYPT_ivsetup(
  ECRYPT_ctx* ctx, 
  const u8* iv)
{
	u32 i=0,tmp;
	u8 S[20];
	
	ctx->state[0]=ctx->init[0]; 
	ctx->state[1]=ctx->init[1];
	ctx->state[2]=ctx->init[2];
		
	ctx->state[2] ^= iv[9]<<16 | iv[8]<<24;
	ctx->state[3] = iv[7] | iv[6]<<8 | iv[5]<<16 | iv[4]<<24;
	ctx->state[4] = iv[3] | iv[2]<<8 | iv[1]<<16 | iv[0]<<24;
	
	
	ctx->carry[0] = 0;
	ctx->carry[1] = 0;
	ctx->carry[2] = 0;
	ctx->carry[3] = 0;
	ctx->carry[4] = 0;
	
	for( i=0; i<20 ; i++)
	{
		ECRYPT_clock(ctx);
		S[i]=ECRYPT_filter(ctx );
	}
	
	ctx->state[0] = S[3]  << 24  | S[2] << 16  | S[1] << 8  | S[0];
	ctx->state[1] = S[7]  << 24  | S[6] << 16  | S[5] << 8  | S[4];
	ctx->state[2] = S[11] << 24  | S[10] << 16 | S[9] << 8  | S[8];
	ctx->state[3] = S[15] << 24  | S[14] << 16 | S[13] << 8 | S[12];
	ctx->state[4] = S[19] << 24  | S[18] << 16 | S[17] << 8 | S[16];
	
	ctx->carry[0] = 0;
	ctx->carry[1] = 0;
	ctx->carry[2] = 0;
	ctx->carry[3] = 0;
	ctx->carry[4] = 0;
	
	for( i=0; i<162 ; i++)
	{
		ECRYPT_clock(ctx);
	}
		
}

void ECRYPT_process_bytes(
  int action,                 /* 0 = encrypt; 1 = decrypt; */
  ECRYPT_ctx* ctx, 
  const u8* input, 
  u8* output, 
  u32 msglen)                /* Message length in bytes. */ 
{
	u32 i;
	for( i=0 ; i< msglen ; i++)
	{
		ECRYPT_clock(ctx);
		output[i] = input[i] ^ ECRYPT_filter(ctx);
	}
}


/* Update the shift register and the carry register of the FCSR */
void ECRYPT_clock(
  ECRYPT_ctx* ctx 
)
{
	u32 feedback;
	u32 buffer[5];
	
	/* expand the feedback bit */
	
	feedback = ((int) (ctx->state[0] << (MAXSHIFT))) >> (MAXSHIFT); 
	/* shift the state */
	
	ctx->state[0] = ctx->state[0] >> 1;
	ctx->state[0] |= (ctx->state[1] & 0x00000001 ) << (MAXSHIFT);

	ctx->state[1] = ctx->state[1] >> 1;
	ctx->state[1] |= (ctx->state[2] & 0x01 ) << (MAXSHIFT);
	
	ctx->state[2] = ctx->state[2] >> 1;
	ctx->state[2] |= (ctx->state[3] & 0x01 ) << (MAXSHIFT);

	ctx->state[3] >>=1;
	ctx->state[3] |= (ctx->state[4] & 0x01 ) << (MAXSHIFT);
	
	ctx->state[4] >>=1;
	/* update the register */
	
	buffer[0] = ctx->state[0] ^ ctx->carry[0]; 
	
	buffer[1] = ctx->state[1] ^ ctx->carry[1];
	buffer[2] = ctx->state[2] ^ ctx->carry[2];
	buffer[3] = ctx->state[3] ^ ctx->carry[3];
	buffer[4] = ctx->state[4] ^ ctx->carry[4];
	
	ctx->carry[0] &= ctx->state[0];
	ctx->carry[1] &= ctx->state[1];
	ctx->carry[2] &= ctx->state[2];
	ctx->carry[3] &= ctx->state[3];
	ctx->carry[4] &= ctx->state[4];

	ctx->carry[0] ^= buffer[0] & (feedback &d0);
	ctx->carry[1] ^= buffer[1] & (feedback &d1);
	ctx->carry[2] ^= buffer[2] & (feedback &d2);
	ctx->carry[3] ^= buffer[3] & (feedback &d3);
	ctx->carry[4] ^= buffer[4] & (feedback &d4);
	
	buffer[0] ^= feedback & d0;
	buffer[1] ^= feedback & d1;
	buffer[2] ^= feedback & d2;
	buffer[3] ^= feedback & d3;
	buffer[4] ^= feedback & d4;
	
	ctx->state[0] = buffer[0];
	ctx->state[1] = buffer[1];
	ctx->state[2] = buffer[2];
	ctx->state[3] = buffer[3];
	ctx->state[4] = buffer[4];
}

/* Produce one byte of keystream from the internal state of the register */
u8 ECRYPT_filter(
  ECRYPT_ctx* ctx 
)
{
	u32 buffer[5];
	
	buffer[0] = ctx->filter[0] & ctx->state[0];
	buffer[1] = ctx->filter[1] & ctx->state[1];
	buffer[2] = ctx->filter[2] & ctx->state[2];
	buffer[3] = ctx->filter[3] & ctx->state[3];
	buffer[4] = ctx->filter[4] & ctx->state[4];
	buffer[0] ^= buffer[1];
	buffer[2] ^= buffer[3];
	
	buffer[0] ^= buffer[2]^ buffer[4];
	

	buffer[0] ^= ( buffer[0] >> 16 );
	buffer[0] ^= ( buffer[0] >> 8);
	return (u8)buffer[0];
}

//#ifdef FFCSRH_EVALUATE
#define MB 1048576
#define NUM_MB 100
int main()
{
	u32 nbByte,i,j;
	clock_t orig, end;
	double time;
	ECRYPT_ctx ctx;
	
	/* key for test vector */
	u8 testKEY[10] = { 0x00, 0x88 , 0x63 , 0x9d, 0x6b , 0xf8 , 0x47 , 0xed , 0x59 , 0xc6 };
	u8 testIV[10]= { 0x00 , 0x11 , 0x22 , 0x33 , 0x44 , 0x55 , 0x66 , 0x77 , 0x88 , 0x99 };
	//u8 encipheredText[9]={ 0xf5, 0x91, 0xce, 0xca, 0x76, 0xef, 0x4a, 0xb6, 0x5e };
	u8 input[128]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	
	 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	u8 output[128];
	//u8 text[9]={'S','O','S','E','M','A','N','U','K'};
	//u8 data=0;
	/* iv for vector test */
	
	
	ECRYPT_keysetup( &ctx , testKEY , ECRYPT_MAXKEYSIZE , ECRYPT_MAXIVSIZE);
	
//	printf("Key loaded\n");
	ECRYPT_ivsetup( &ctx , testIV );
//	printf("IV loaded\n");

//while(1)	
	ECRYPT_process_bytes( 0, &ctx , input , output , 128); 
	
	return 0;
}
//#endif





