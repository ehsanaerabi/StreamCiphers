extern unsigned long long getcyclecount();

/* This code is based on the
 *  Reference implementation of the TRIVIUM stream cipher
 *  Christophe De Canniere, K.U.Leuven.
 */

typedef unsigned int  u32;
typedef unsigned char u8;

typedef struct {
  u32 keylen;
  u32 ivlen;
  u8  s[40];
  u8  key[10];

} ECRYPT_ctx;

#define U32TO8_LITTLE(p, v) (((u32*)(p))[0] = U32TO32_LITTLE(v))
#define U8TO32_LITTLE(p) U32TO32_LITTLE(((u32*)(p))[0])
#define U32TO32_LITTLE(v) (v)

#define S00(a, b) ((S(a, 1) << ( 32 - (b))))
#define S32(a, b) ((S(a, 2) << ( 64 - (b))) | (S(a, 1) >> ((b) - 32)))
#define S64(a, b) ((S(a, 3) << ( 96 - (b))) | (S(a, 2) >> ((b) - 64)))
#define S96(a, b) ((S(a, 4) << (128 - (b))) | (S(a, 3) >> ((b) - 96)))

#define UPDATE()                                                             \
  do {                                                                       \
    T(1) = S64(1,  66) ^ S64(1,  93);                                        \
    T(2) = S64(2,  69) ^ S64(2,  84);                                        \
    T(3) = S64(3,  66) ^ S96(3, 111);                                        \
                                                                             \
    Z(T(1) ^ T(2) ^ T(3));                                                   \
                                                                             \
    T(1) ^= (S64(1,  91) & S64(1,  92)) ^ S64(2,  78);                       \
    T(2) ^= (S64(2,  82) & S64(2,  83)) ^ S64(3,  87);                       \
    T(3) ^= (S96(3, 109) & S96(3, 110)) ^ S64(1,  69);                       \
  } while (0)

#define ROTATE()                                                             \
  do {                                                                       \
    S(1, 3) = S(1, 2); S(1, 2) = S(1, 1); S(1, 1) = T(3);                    \
    S(2, 3) = S(2, 2); S(2, 2) = S(2, 1); S(2, 1) = T(1);                    \
    S(3, 4) = S(3, 3); S(3, 3) = S(3, 2); S(3, 2) = S(3, 1); S(3, 1) = T(2); \
  } while (0)

#define LOAD(s)                                                              \
  do {                                                                       \
    S(1, 1) = U8TO32_LITTLE((s) +  0);                                       \
    S(1, 2) = U8TO32_LITTLE((s) +  4);                                       \
    S(1, 3) = U8TO32_LITTLE((s) +  8);                                       \
                                                                             \
    S(2, 1) = U8TO32_LITTLE((s) + 12);                                       \
    S(2, 2) = U8TO32_LITTLE((s) + 16);                                       \
    S(2, 3) = U8TO32_LITTLE((s) + 20);                                       \
                                                                             \
    S(3, 1) = U8TO32_LITTLE((s) + 24);                                       \
    S(3, 2) = U8TO32_LITTLE((s) + 28);                                       \
    S(3, 3) = U8TO32_LITTLE((s) + 32);                                       \
    S(3, 4) = U8TO32_LITTLE((s) + 36);                                       \
  } while (0)

#define STORE(s)                                                            \
  do {                                                                      \
    U32TO8_LITTLE((s) +  0, S(1, 1));                                       \
    U32TO8_LITTLE((s) +  4, S(1, 2));                                       \
    U32TO8_LITTLE((s) +  8, S(1, 3));                                       \
                                                                            \
    U32TO8_LITTLE((s) + 12, S(2, 1));                                       \
    U32TO8_LITTLE((s) + 16, S(2, 2));                                       \
    U32TO8_LITTLE((s) + 20, S(2, 3));                                       \
                                                                            \
    U32TO8_LITTLE((s) + 24, S(3, 1));                                       \
    U32TO8_LITTLE((s) + 28, S(3, 2));                                       \
    U32TO8_LITTLE((s) + 32, S(3, 3));                                       \
    U32TO8_LITTLE((s) + 36, S(3, 4));                                       \
  } while (0)

void ECRYPT_keysetup(
  ECRYPT_ctx* ctx, 
  const u8* key, 
  u32 keysize,
  u32 ivsize)
{
  u32 i;

  ctx->keylen = (keysize + 7) / 8;
  ctx->ivlen = (ivsize + 7) / 8;

  for (i = 0; i < ctx->keylen; ++i)
    ctx->key[i] = key[i];
}

#define S(a, n) (s##a##n)
#define T(a) (t##a)

void ECRYPT_ivsetup(
  ECRYPT_ctx* ctx, 
  const u8* iv)
{
  u32 i;

  u32 s11, s12, s13;
  u32 s21, s22, s23;
  u32 s31, s32, s33, s34;

  for (i = 0; i < ctx->keylen; ++i)
    ctx->s[i] = ctx->key[i];

  for (i = ctx->keylen; i < 12; ++i)
    ctx->s[i] = 0;

  for (i = 0; i < ctx->ivlen; ++i)
    ctx->s[i + 12] = iv[i];

  for (i = ctx->ivlen; i < 12; ++i)
    ctx->s[i + 12] = 0;

  for (i = 0; i < 13; ++i)
    ctx->s[i + 24] = 0;

  ctx->s[13 + 24] = 0x70;

  LOAD(ctx->s);

#define Z(w)

  for (i = 0; i < 4 * 9; ++i)
    {
      u32 t1, t2, t3;
      
      UPDATE();
      ROTATE();
    }

  STORE(ctx->s);
}

void ECRYPT_process_bytes(
  int action,
  ECRYPT_ctx* ctx, 
  const u8* input, 
  u8* output, 
  u32 msglen)
{
  u32 i;

  u32 s11, s12, s13;
  u32 s21, s22, s23;
  u32 s31, s32, s33, s34;

  u32 z;

  LOAD(ctx->s);

#undef Z
#define Z(w) (U32TO8_LITTLE(output + 4 * i, U8TO32_LITTLE(input + 4 * i) ^ w))

  for (i = 0; i < msglen / 4; ++i)
    {
      u32 t1, t2, t3;
      
      UPDATE();
      ROTATE();
    }

#undef Z
#define Z(w) (z = w)

  STORE(ctx->s);
}

/* ------------------------------------------------------------------------- */

int main() {
  ECRYPT_ctx trivium_state;

  u8 key[10] = {0x80, 0, 0, 0, 0, 0, 0, 0};
  u8 iv[10]  = {   0, 0, 0, 0, 0, 0, 0, 0};

  u8 input[128];
  u8 output[128];

  unsigned i;

  //unsigned long long c0, c1, c2;

 // memset(input, 0, 512);

 // c0 = getcyclecount();

  ECRYPT_keysetup(&trivium_state, key, 10, 10);
  ECRYPT_ivsetup (&trivium_state, iv);

//  c1 = getcyclecount();


//while(1)

  ECRYPT_process_bytes(0, &trivium_state, input, output, 128);



  return 0;

}
