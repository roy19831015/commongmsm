#include "textflag.h"

#define x V0
#define y V1
#define t0 V2
#define t1 V3
#define t2 V4
#define t3 V5
#define ZERO V16
#define FLIP_MASK V17

#define XTMP6 V6
#define XTMP7 V7

// shuffle byte order from LE to BE
DATA flip_mask<>+0x00(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x08(SB)/8, $0x0c0d0e0f08090a0b
GLOBL flip_mask<>(SB), RODATA, $16

//nibble mask
DATA nibble_mask<>+0x00(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA nibble_mask<>+0x08(SB)/8, $0x0F0F0F0F0F0F0F0F
GLOBL nibble_mask<>(SB), RODATA, $16

// inverse shift rows
DATA inverse_shift_rows<>+0x00(SB)/8, $0x0B0E0104070A0D00
DATA inverse_shift_rows<>+0x08(SB)/8, $0x0306090C0F020508 
GLOBL inverse_shift_rows<>(SB), RODATA, $16

// Affine transform 1 (low and high hibbles)
DATA m1_low<>+0x00(SB)/8, $0x9197E2E474720701
DATA m1_low<>+0x08(SB)/8, $0xC7C1B4B222245157
GLOBL m1_low<>(SB), RODATA, $16

DATA m1_high<>+0x00(SB)/8, $0xE240AB09EB49A200
DATA m1_high<>+0x08(SB)/8, $0xF052B91BF95BB012  
GLOBL m1_high<>(SB), RODATA, $16

// Affine transform 2 (low and high hibbles)
DATA m2_low<>+0x00(SB)/8, $0x5B67F2CEA19D0834
DATA m2_low<>+0x08(SB)/8, $0xEDD14478172BBE82
GLOBL m2_low<>(SB), RODATA, $16

DATA m2_high<>+0x00(SB)/8, $0xAE7201DD73AFDC00
DATA m2_high<>+0x08(SB)/8, $0x11CDBE62CC1063BF
GLOBL m2_high<>(SB), RODATA, $16

// left rotations of 32-bit words by 8-bit increments
DATA r08_mask<>+0x00(SB)/8, $0x0605040702010003
DATA r08_mask<>+0x08(SB)/8, $0x0E0D0C0F0A09080B  
GLOBL r08_mask<>(SB), RODATA, $16

DATA r16_mask<>+0x00(SB)/8, $0x0504070601000302
DATA r16_mask<>+0x08(SB)/8, $0x0D0C0F0E09080B0A   
GLOBL r16_mask<>(SB), RODATA, $16

DATA r24_mask<>+0x00(SB)/8, $0x0407060500030201
DATA r24_mask<>+0x08(SB)/8, $0x0C0F0E0D080B0A09  
GLOBL r24_mask<>(SB), RODATA, $16

DATA fk_mask<>+0x00(SB)/8, $0x56aa3350a3b1bac6
DATA fk_mask<>+0x08(SB)/8, $0xb27022dc677d9197
GLOBL fk_mask<>(SB), RODATA, $16

#define SM4_SBOX(x, y) \
  ;                                              \ //#############################  inner affine ############################//
  LDP	nibble_mask<>(SB), (R0, R1);               \
	VMOV	R0, XTMP6.D[0];                          \
	VMOV	R1, XTMP6.D[1];                          \
  VAND x.B16, XTMP6.B16, XTMP7.B16;              \
  LDP	m1_low<>(SB), (R0, R1);                    \
	VMOV	R0, y.D[0];                              \
	VMOV	R1, y.D[1];                              \  
  VTBL XTMP7.B16, [y.B16], y.B16;                \
  VUSHR $4, x.D2, x.D2;                          \
  VAND x.B16, XTMP6.B16, XTMP7.B16;              \
  LDP	m1_low<>(SB), (R0, R1);                    \
	VMOV	R0, V8.D[0];                             \
	VMOV	R1, V8.D[1];                             \  
  VTBL XTMP7.B16, [V8.B16], XTMP7.B16;           \
  VEOR y.B16, XTMP7.B16, x.B16;                  \
  LDP	inverse_shift_rows<>(SB), (R0, R1);        \
	VMOV	R0, V8.D[0];                             \
	VMOV	R1, V8.D[1];                             \    
  VTBL V8.B16, [x.B16], x.B16;                   \
  AESE ZERO.B16, x.B16;                          \	
  VAND x.B16, XTMP6.B16, XTMP7.B16;              \
  LDP	m2_low<>(SB), (R0, R1);                    \
	VMOV	R0, y.D[0];                              \
	VMOV	R1, y.D[1];                              \  
  VTBL XTMP7.B16, [y.B16], y.B16;                \
  VUSHR $4, x.D2, x.D2;                          \
  VAND x.B16, XTMP6.B16, XTMP7.B16;              \
  LDP	m2_high<>(SB), (R0, R1);                   \
	VMOV	R0, V8.D[0];                             \
	VMOV	R1, V8.D[1];                             \  
  VTBL XTMP7.B16, [V8.B16], XTMP7.B16;           \
  VEOR y.B16, XTMP7.B16, x.B16;                  \
  

#define SM4_TAO_L1(x, y)         \
  SM4_SBOX(x, y);                              \
  ;                                            \ //####################  4 parallel L1 linear transforms ##################//
  LDP	r08_mask<>(SB), (R0, R1);                \
	VMOV	R0, XTMP7.D[0];                        \
	VMOV	R1, XTMP7.D[1];                        \  
  VTBL XTMP7.B16, [x.B16], y.B16;              \
  VEOR y.B16, x.B16, y.B16;                    \
  LDP	r16_mask<>(SB), (R0, R1);                \
	VMOV	R0, V8.D[0];                           \
	VMOV	R1, V8.D[1];                           \   
  VTBL V8.B16, [x.B16], XTMP7.B16;             \
  VEOR XTMP7.B16, y.B16, y.B16;                \
  VSHL $2, y.S4, XTMP7.S4;                     \
  VUSHR $32, y.S4, y.S4;                       \
  VEOR y.B16, XTMP7.B16, y.B16;                \
  LDP	r24_mask<>(SB), (R0, R1);                \
	VMOV	R0, V8.D[0];                           \
	VMOV	R1, V8.D[1];                           \    
  VTBL V8.B16, [x.B16], XTMP7.B16;             \
  VEOR XTMP7.B16, x.B16, x.B16;                \
  VEOR y.B16, x.B16, x.B16

#define SM4_TAO_L2(x, y)         \
  SM4_SBOX(x, y);                             \
  ;                                           \ //####################  4 parallel L2 linear transforms ##################//
  VSHL $13, x.S4, XTMP6.S4;                   \
  VUSHR $19, x.S4, y.S4;                      \
  VORR XTMP6.B16, y.B16, y.B16;               \
  VSHL $23, x.S4, XTMP6.S4;                   \
  VUSHR $9, x.S4, XTMP7.S4;                   \
  VORR XTMP6.B16, XTMP7.B16, XTMP7.B16;       \
  VEOR XTMP7.B16, y.B16, y.B16;               \
  VEOR x.B16, y.B16, x.B16

// func expandKeyAsm(key *byte, ck, enc, dec *uint32)
TEXT ·expandKeyAsm(SB),NOSPLIT,$0
  MOVD	key+0(FP), R8
  MOVD  ck+8(FP), R9
  MOVD  enc+16(FP), R10
  MOVD  dec+24(FP), R11

  VLD1 (R8), [t0.B16]; 
  LDP	flip_mask<>(SB), (R0, R1)
	VMOV	R0, FLIP_MASK.D[0]
	VMOV	R1, FLIP_MASK.D[1]
  VTBL FLIP_MASK.B16, [t0.B16], t0.B16
  LDP	fk_mask<>(SB), (R0, R1)
	VMOV	R0, XTMP7.D[0]
	VMOV	R1, XTMP7.D[1]
  VEOR t0.B16, XTMP7.B16, t0.B16
  VMOV t0.S[1], t1.S[0]
  VMOV t0.S[2], t2.S[0]
  VMOV t0.S[3], t3.S[0]

  EOR R0, R0
  ADD $124, R11
  VEOR ZERO.B16, ZERO.B16, ZERO.B16

loop:
  MOVW.P 4(R9), R19
  VMOV R19, x.S[0]
  VEOR t1.B16, x.B16, x.B16
  VEOR t2.B16, x.B16, x.B16
  VEOR t3.B16, x.B16, x.B16
  SM4_TAO_L2(x, y)
  VEOR x.B16, t0.B16, t0.B16
  VMOV t0.S[0], R2
  MOVW.P R2, 4(R10)
  MOVW.P R2, -4(R11)

  MOVW.P 4(R9), R19
  VMOV R19, x.S[0]
  VEOR t0.B16, x.B16, x.B16
  VEOR t2.B16, x.B16, x.B16
  VEOR t3.B16, x.B16, x.B16
  SM4_TAO_L2(x, y)
  VEOR x.B16, t1.B16, t1.B16
  VMOV t1.S[0], R2
  MOVW.P R2, 4(R10)
  MOVW.P R2, -4(R11)

  MOVW.P 4(R9), R19
  VMOV R19, x.S[0]
  VEOR t0.B16, x.B16, x.B16
  VEOR t1.B16, x.B16, x.B16
  VEOR t3.B16, x.B16, x.B16
  SM4_TAO_L2(x, y)
  VEOR x.B16, t2.B16, t2.B16
  VMOV t2.S[0], R2
  MOVW.P R2, 4(R10)
  MOVW.P R2, -4(R11)

  MOVW.P 4(R9), R19
  VMOV R19, x.S[0]
  VEOR t0.B16, x.B16, x.B16
  VEOR t1.B16, x.B16, x.B16
  VEOR t2.B16, x.B16, x.B16
  SM4_TAO_L2(x, y)
  VEOR x.B16, t3.B16, t3.B16
  VMOV t3.S[0], R2
  MOVW.P R2, 4(R10)
  MOVW.P R2, -4(R11)

  ADD $16, R0 
  CMP $4*32, R0
  BNE loop

expand_end:  
  RET 

// func encryptBlocksAsm(xk *uint32, dst, src *byte)
TEXT ·encryptBlocksAsm(SB),NOSPLIT,$0
  MOVD xk+0(FP), R8
  MOVD dst+8(FP), R9
  MOVD src+16(FP), R10

  LDPW	(0*8)(R10), (R19, R20)
  LDPW	(1*8)(R10), (R21, R22)
  VMOV R19, t0.S[0]
  VMOV R20, t1.S[0]
  VMOV R21, t2.S[0]
  VMOV R22, t3.S[0]
  
  LDPW	(2*8)(R10), (R19, R20)
  LDPW	(3*8)(R10), (R21, R22)
  VMOV R19, t0.S[1]
  VMOV R20, t1.S[1]
  VMOV R21, t2.S[1]
  VMOV R22, t3.S[1]

  LDPW	(4*8)(R10), (R19, R20)
  LDPW	(5*8)(R10), (R21, R22)
  VMOV R19, t0.S[2]
  VMOV R20, t1.S[2]
  VMOV R21, t2.S[2]
  VMOV R22, t3.S[2]  

  LDPW	(6*8)(R10), (R19, R20)
  LDPW	(7*8)(R10), (R21, R22)
  VMOV R19, t0.S[3]
  VMOV R20, t1.S[3]
  VMOV R21, t2.S[3]
  VMOV R22, t3.S[3]    

  LDP	flip_mask<>(SB), (R0, R1)
	VMOV	R0, FLIP_MASK.D[0]
	VMOV	R1, FLIP_MASK.D[1]

  VTBL FLIP_MASK.B16, [t0.B16], t0.B16
  VTBL FLIP_MASK.B16, [t1.B16], t1.B16
  VTBL FLIP_MASK.B16, [t2.B16], t2.B16
  VTBL FLIP_MASK.B16, [t3.B16], t3.B16

  VEOR ZERO.B16, ZERO.B16, ZERO.B16
  
  EOR R0, R0

loop:
  MOVW.P 4(R8), R19
  VMOV R19, x.S[0]
  VMOV R19, x.S[1]
  VMOV R19, x.S[2]
  VMOV R19, x.S[3]
  VEOR t1.B16, x.B16, x.B16
  VEOR t2.B16, x.B16, x.B16
  VEOR t3.B16, x.B16, x.B16
  SM4_TAO_L1(x, y)
  VEOR x.B16, t0.B16, t0.B16

  MOVW.P 4(R8), R19
  VMOV R19, x.S[0]
  VMOV R19, x.S[1]
  VMOV R19, x.S[2]
  VMOV R19, x.S[3]
  VEOR t0.B16, x.B16, x.B16
  VEOR t2.B16, x.B16, x.B16
  VEOR t3.B16, x.B16, x.B16
  SM4_TAO_L1(x, y)
  VEOR x.B16, t1.B16, t1.B16

  MOVW.P 4(R8), R19
  VMOV R19, x.S[0]
  VMOV R19, x.S[1]
  VMOV R19, x.S[2]
  VMOV R19, x.S[3]
  VEOR t0.B16, x.B16, x.B16
  VEOR t1.B16, x.B16, x.B16
  VEOR t3.B16, x.B16, x.B16
  SM4_TAO_L1(x, y)
  VEOR x.B16, t2.B16, t2.B16
  ADD $4, R0

  MOVW.P 4(R8), R19
  VMOV R19, x.S[0]
  VMOV R19, x.S[1]
  VMOV R19, x.S[2]
  VMOV R19, x.S[3]
  VEOR t0.B16, x.B16, x.B16
  VEOR t1.B16, x.B16, x.B16
  VEOR t2.B16, x.B16, x.B16
  SM4_TAO_L1(x, y)
  VEOR x.B16, t3.B16, t3.B16

  ADD $16, R0
  CMP $4*32, R0
  BNE loop

  VTBL FLIP_MASK.B16, [t0.B16], t0.B16
  VTBL FLIP_MASK.B16, [t1.B16], t1.B16
  VTBL FLIP_MASK.B16, [t2.B16], t2.B16
  VTBL FLIP_MASK.B16, [t3.B16], t3.B16

  VMOV t3.S[0], V8.S[0]
  VMOV t2.S[0], V8.S[1]
  VMOV t1.S[0], V8.S[2]
  VMOV t0.S[0], V8.S[3]
  VST1.P	[V8.B16], 16(R9)

  VMOV t3.S[1], V8.S[0]
  VMOV t2.S[1], V8.S[1]
  VMOV t1.S[1], V8.S[2]
  VMOV t0.S[1], V8.S[3]
  VST1.P	[V8.B16], 16(R9)

  VMOV t3.S[2], V8.S[0]
  VMOV t2.S[2], V8.S[1]
  VMOV t1.S[2], V8.S[2]
  VMOV t0.S[2], V8.S[3]
  VST1.P	[V8.B16], 16(R9)

  VMOV t3.S[3], V8.S[0]
  VMOV t2.S[3], V8.S[1]
  VMOV t1.S[3], V8.S[2]
  VMOV t0.S[3], V8.S[3]
  VST1	[V8.B16], (R9)

done_sm4:
	RET


// func encryptBlockAsm(xk *uint32, dst, src *byte)
TEXT ·encryptBlockAsm(SB),NOSPLIT,$0
  MOVD xk+0(FP), R8
  MOVD dst+8(FP), R9
  MOVD src+16(FP), R10

  LDPW	(0*8)(R10), (R19, R20)
  LDPW	(1*8)(R10), (R21, R22)
  REVW R19, R19
  REVW R20, R20
  REVW R21, R21
  REVW R22, R22
  VMOV R19, t0.S[0]
  VMOV R20, t1.S[0]
  VMOV R21, t2.S[0]
  VMOV R22, t3.S[0]

  VEOR ZERO.B16, ZERO.B16, ZERO.B16
  LDP	flip_mask<>(SB), (R0, R1)
	VMOV	R0, FLIP_MASK.D[0]
	VMOV	R1, FLIP_MASK.D[1]
  EOR R0, R0

loop:
  MOVW.P 4(R8), R19
  VMOV R19, x.S[0]
  VMOV R19, x.S[1]
  VMOV R19, x.S[2]
  VMOV R19, x.S[3]
  VEOR t1.B16, x.B16, x.B16
  VEOR t2.B16, x.B16, x.B16
  VEOR t3.B16, x.B16, x.B16
  SM4_TAO_L1(x, y)
  VEOR x.B16, t0.B16, t0.B16

  MOVW.P 4(R8), R19
  VMOV R19, x.S[0]
  VMOV R19, x.S[1]
  VMOV R19, x.S[2]
  VMOV R19, x.S[3]
  VEOR t0.B16, x.B16, x.B16
  VEOR t2.B16, x.B16, x.B16
  VEOR t3.B16, x.B16, x.B16
  SM4_TAO_L1(x, y)
  VEOR x.B16, t1.B16, t1.B16

  MOVW.P 4(R8), R19
  VMOV R19, x.S[0]
  VMOV R19, x.S[1]
  VMOV R19, x.S[2]
  VMOV R19, x.S[3]
  VEOR t0.B16, x.B16, x.B16
  VEOR t1.B16, x.B16, x.B16
  VEOR t3.B16, x.B16, x.B16
  SM4_TAO_L1(x, y)
  VEOR x.B16, t2.B16, t2.B16

  MOVW.P 4(R8), R19
  VMOV R19, x.S[0]
  VMOV R19, x.S[1]
  VMOV R19, x.S[2]
  VMOV R19, x.S[3]
  VEOR t0.B16, x.B16, x.B16
  VEOR t1.B16, x.B16, x.B16
  VEOR t2.B16, x.B16, x.B16
  SM4_TAO_L1(x, y)
  VEOR x.B16, t3.B16, t3.B16

  ADD $16, R0
  CMP $4*32, R0
  BNE loop

  VTBL FLIP_MASK.B16, [t0.B16], t0.B16
  VTBL FLIP_MASK.B16, [t1.B16], t1.B16
  VTBL FLIP_MASK.B16, [t2.B16], t2.B16
  VTBL FLIP_MASK.B16, [t3.B16], t3.B16

  VMOV t3.S[0], V8.S[0]
  VMOV t2.S[0], V8.S[1]
  VMOV t1.S[0], V8.S[2]
  VMOV t0.S[0], V8.S[3]
  VST1	[V8.B16], (R9)

done_sm4:
	RET  