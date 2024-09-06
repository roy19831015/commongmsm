// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

#include "textflag.h"

// For P9 instruction emulation
#define ESPERMW  V21 // Endian swapping permute into BE
#define TMP2    V22  // Temporary for STOREWORDS

DATA ·mask+0x00(SB)/8, $0x0c0d0e0f08090a0b // Permute for vector doubleword endian swap
DATA ·mask+0x08(SB)/8, $0x0405060700010203
DATA ·mask+0x10(SB)/8, $0x0001020310111213 // Permute for transpose matrix
DATA ·mask+0x18(SB)/8, $0x0405060714151617
DATA ·mask+0x20(SB)/8, $0x08090a0b18191a1b
DATA ·mask+0x28(SB)/8, $0x0c0d0e0f1c1d1e1f
DATA ·mask+0x30(SB)/8, $0x0001020304050607
DATA ·mask+0x38(SB)/8, $0x1011121314151617
DATA ·mask+0x40(SB)/8, $0x08090a0b0c0d0e0f
DATA ·mask+0x48(SB)/8, $0x18191a1b1c1d1e1f
DATA ·mask+0x50(SB)/8, $0x0b0a09080f0e0d0c // Permute for vector doubleword endian swap
DATA ·mask+0x58(SB)/8, $0x0302010007060504
GLOBL ·mask(SB), RODATA, $96

#ifdef GOARCH_ppc64le
#define NEEDS_ESPERM

#define LOADWORDS(RA,RB,VT) \
	LXVD2X	(RA+RB), VT \
	VPERM	VT, VT, ESPERMW, VT

#define STOREWORDS(VS,RA,RB) \
	VPERM	VS, VS, ESPERMW, TMP2 \
	STXVD2X	TMP2, (RA+RB)

#else
#define LOADWORDS(RA,RB,VT)  LXVD2X	(RA+RB), VT
#define STOREWORDS(VS,RA,RB) STXVD2X	VS, (RA+RB)	
#endif // defined(GOARCH_ppc64le)

#define TRANSPOSE_MATRIX(T0, T1, T2, T3, M0, M1, M2, M3, TMP0, TMP1, TMP2, TMP3) \
	VPERM T0, T1, M0, TMP0; \
	VPERM T2, T3, M0, TMP1; \
	VPERM T0, T1, M1, TMP2; \
	VPERM T2, T3, M1, TMP3; \
	VPERM TMP0, TMP1, M2, T0; \
	VPERM TMP0, TMP1, M3, T1; \
	VPERM TMP2, TMP3, M2, T2; \
	VPERM TMP2, TMP3, M3, T3

// transposeMatrix(dig **[8]uint32)
TEXT ·transposeMatrix(SB),NOSPLIT,$0
	MOVD	dig+0(FP), R3
	MOVD 	$8, R5
	MOVD 	$16, R6
	MOVD 	$24, R7
	MOVD 	$32, R8
	MOVD 	$48, R9

#ifdef NEEDS_ESPERM
	MOVD	$·mask(SB), R4
	LVX	(R4), ESPERMW
	ADD	$0x10, R4
#else
	MOVD	$·mask+0x10(SB), R4
#endif
	LXVD2X 	(R0)(R4), V8
	LXVD2X 	(R6)(R4), V9
	LXVD2X 	(R8)(R4), V10
	LXVD2X 	(R9)(R4), V11

	MOVD 	(R0)(R3), R4
	LXVW4X 	(R0)(R4), V0
	LXVW4X 	(R6)(R4), V4
	MOVD 	(R5)(R3), R4
	LXVW4X 	(R0)(R4), V1
	LXVW4X 	(R6)(R4), V5	
	MOVD 	(R6)(R3), R4
	LXVW4X 	(R0)(R4), V2
	LXVW4X 	(R6)(R4), V6	
	MOVD 	(R7)(R3), R4
	LXVW4X 	(R0)(R4), V3
	LXVW4X 	(R6)(R4), V7


	TRANSPOSE_MATRIX(V0, V1, V2, V3, V8, V9, V10, V11, V12, V13, V14, V15)
	TRANSPOSE_MATRIX(V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15)

	MOVD 	(R0)(R3), R4
	STXVW4X	V0, (R0)(R4)
	STXVW4X	V4, (R6)(R4)
	MOVD 	(R5)(R3), R4
	STXVW4X	V1, (R0)(R4)
	STXVW4X	V5, (R6)(R4)
	MOVD 	(R6)(R3), R4
	STXVW4X	V2, (R0)(R4)
	STXVW4X	V6, (R6)(R4)
	MOVD 	(R7)(R3), R4
	STXVW4X	V3, (R0)(R4)
	STXVW4X	V7, (R6)(R4)

	RET

#ifdef GOARCH_ppc64le
#define NEEDS_ESPERM

#define PPC64X_STXVD2X(VS,RA,RB) \
	VPERM	VS, VS, ESPERMW, TMP2 \
	STXVD2X	TMP2, (RA+RB)

#else
#define STORED2X(VS,RA,RB) STXVD2X	VS, (RA+RB)	
#endif // defined(GOARCH_ppc64le)

// func copyResultsBy4(dig *uint32, dst *byte)
TEXT ·copyResultsBy4(SB),NOSPLIT,$0
	MOVD	dig+0(FP), R3
	MOVD	dst+8(FP), R4

#ifdef NEEDS_ESPERM	
	MOVD	$·mask+0x80(SB), R5
	LVX	(R5), ESPERMW
#endif

	LXVD2X 	(R0)(R3), V0
	PPC64X_STXVD2X(V0, R0, R4)

	MOVD	$16, R5
	LXVD2X 	(R5)(R3), V0
	PPC64X_STXVD2X(V0, R0, R4)
	
	ADD 	$16, R5
	LXVD2X 	(R5)(R3), V0
	PPC64X_STXVD2X(V0, R0, R4)

	ADD 	$16, R5
	LXVD2X 	(R5)(R3), V0
	PPC64X_STXVD2X(V0, R0, R4)

	ADD 	$16, R5
	LXVD2X 	(R5)(R3), V0
	PPC64X_STXVD2X(V0, R0, R4)

	ADD 	$16, R5
	LXVD2X 	(R5)(R3), V0
	PPC64X_STXVD2X(V0, R0, R4)

	ADD 	$16, R5
	LXVD2X 	(R5)(R3), V0
	PPC64X_STXVD2X(V0, R0, R4)

	ADD 	$16, R5
	LXVD2X 	(R5)(R3), V0
	PPC64X_STXVD2X(V0, R0, R4)

	RET
