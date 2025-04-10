// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build 386 || amd64 || amd64p32

package cpu

import "runtime"

const cacheLineSize = 64

func initOptions() {
	options = []option{
		{Name: "adx", Feature: &X86.HasADX},
		{Name: "aes", Feature: &X86.HasAES},
		{Name: "avx", Feature: &X86.HasAVX},
		{Name: "avx2", Feature: &X86.HasAVX2},
		{Name: "avx512", Feature: &X86.HasAVX512},
		{Name: "avx512f", Feature: &X86.HasAVX512F},
		{Name: "avx512cd", Feature: &X86.HasAVX512CD},
		{Name: "avx512er", Feature: &X86.HasAVX512ER},
		{Name: "avx512pf", Feature: &X86.HasAVX512PF},
		{Name: "avx512vl", Feature: &X86.HasAVX512VL},
		{Name: "avx512bw", Feature: &X86.HasAVX512BW},
		{Name: "avx512dq", Feature: &X86.HasAVX512DQ},
		{Name: "avx512ifma", Feature: &X86.HasAVX512IFMA},
		{Name: "avx512vbmi", Feature: &X86.HasAVX512VBMI},
		{Name: "avx512vnniw", Feature: &X86.HasAVX5124VNNIW},
		{Name: "avx5124fmaps", Feature: &X86.HasAVX5124FMAPS},
		{Name: "avx512vpopcntdq", Feature: &X86.HasAVX512VPOPCNTDQ},
		{Name: "avx512vpclmulqdq", Feature: &X86.HasAVX512VPCLMULQDQ},
		{Name: "avx512vnni", Feature: &X86.HasAVX512VNNI},
		{Name: "avx512gfni", Feature: &X86.HasAVX512GFNI},
		{Name: "avx512vaes", Feature: &X86.HasAVX512VAES},
		{Name: "avx512vbmi2", Feature: &X86.HasAVX512VBMI2},
		{Name: "avx512bitalg", Feature: &X86.HasAVX512BITALG},
		{Name: "avx512bf16", Feature: &X86.HasAVX512BF16},
		{Name: "amxtile", Feature: &X86.HasAMXTile},
		{Name: "amxint8", Feature: &X86.HasAMXInt8},
		{Name: "amxbf16", Feature: &X86.HasAMXBF16},
		{Name: "bmi1", Feature: &X86.HasBMI1},
		{Name: "bmi2", Feature: &X86.HasBMI2},
		{Name: "cx16", Feature: &X86.HasCX16},
		{Name: "erms", Feature: &X86.HasERMS},
		{Name: "fma", Feature: &X86.HasFMA},
		{Name: "osxsave", Feature: &X86.HasOSXSAVE},
		{Name: "pclmulqdq", Feature: &X86.HasPCLMULQDQ},
		{Name: "popcnt", Feature: &X86.HasPOPCNT},
		{Name: "rdrand", Feature: &X86.HasRDRAND},
		{Name: "rdseed", Feature: &X86.HasRDSEED},
		{Name: "sse3", Feature: &X86.HasSSE3},
		{Name: "sse41", Feature: &X86.HasSSE41},
		{Name: "sse42", Feature: &X86.HasSSE42},
		{Name: "ssse3", Feature: &X86.HasSSSE3},
		{Name: "avxifma", Feature: &X86.HasAVXIFMA},
		{Name: "avxvnni", Feature: &X86.HasAVXVNNI},
		{Name: "avxvnniint8", Feature: &X86.HasAVXVNNIInt8},

		// These capabilities should always be enabled on amd64:
		{Name: "sse2", Feature: &X86.HasSSE2, Required: runtime.GOARCH == "amd64"},
	}
}

func archInit() {

	Initialized = true

	maxID, _, _, _ := cpuid(0, 0)

	if maxID < 1 {
		return
	}

	_, _, ecx1, edx1 := cpuid(1, 0)
	X86.HasSSE2 = isSet(26, edx1)

	X86.HasSSE3 = isSet(0, ecx1)      // Check presence of SSE3 - bit 0 of ECX
	X86.HasPCLMULQDQ = isSet(1, ecx1) // Check presence of PCLMULQDQ - bit 1 of ECX
	X86.HasSSSE3 = isSet(9, ecx1)     // Check presence of SSSE3 - bit 9 of ECX
	X86.HasFMA = isSet(12, ecx1)      // Check presence of FMA - bit 12 of ECX
	X86.HasCX16 = isSet(13, ecx1)     // Check presence of CX16 - bit 13 of ECX
	X86.HasSSE41 = isSet(19, ecx1)    // Check presence of SSE4.1 - bit 19 of ECX
	X86.HasSSE42 = isSet(20, ecx1)    // Check presence of SSE4.2 - bit 20 of ECX
	X86.HasPOPCNT = isSet(23, ecx1)   // Check presence of POPCNT - bit 23 of ECX
	X86.HasAES = isSet(25, ecx1)      // Check presence of AESNI - bit 25 of ECX
	X86.HasOSXSAVE = isSet(27, ecx1)  // Check presence of OSXSAVE - bit 27 of ECX
	X86.HasRDRAND = isSet(30, ecx1)   // Check presence of RDRAND - bit 30 of ECX

	var osSupportsAVX, osSupportsAVX512 bool
	// For XGETBV, OSXSAVE bit is required and sufficient.
	if X86.HasOSXSAVE {
		eax, _ := xgetbv()
		// Check if XMM and YMM registers have OS support.
		osSupportsAVX = isSet(1, eax) && isSet(2, eax)

		if runtime.GOOS == "darwin" {
			// Darwin requires special AVX512 checks, see cpu_darwin_x86.go
			osSupportsAVX512 = osSupportsAVX && darwinSupportsAVX512()
		} else {
			// Check if OPMASK and ZMM registers have OS support.
			osSupportsAVX512 = osSupportsAVX && isSet(5, eax) && isSet(6, eax) && isSet(7, eax)
		}
	}

	X86.HasAVX = isSet(28, ecx1) && osSupportsAVX

	if maxID < 7 {
		return
	}

	eax7, ebx7, ecx7, edx7 := cpuid(7, 0)
	X86.HasBMI1 = isSet(3, ebx7)                  // Check presence of BMI1 - bit 3 of EBX
	X86.HasAVX2 = isSet(5, ebx7) && osSupportsAVX // Check presence of AVX2 - bit 5 of EBX
	X86.HasBMI2 = isSet(8, ebx7)                  // Check presence of BMI2 - bit 8 of EBX
	X86.HasERMS = isSet(9, ebx7)
	X86.HasRDSEED = isSet(18, ebx7)
	X86.HasADX = isSet(19, ebx7)

	X86.HasAVX512 = isSet(16, ebx7) && osSupportsAVX512 // Because avx-512 foundation is the core required extension
	if X86.HasAVX512 {
		X86.HasAVX512F = true
		X86.HasAVX512CD = isSet(28, ebx7)         // Check presence of AVX512CD - bit 28 of EBX
		X86.HasAVX512ER = isSet(27, ebx7)         // Check presence of AVX512ER - bit 27 of EBX
		X86.HasAVX512PF = isSet(26, ebx7)         // Check presence of AVX512PF - bit 26 of EBX
		X86.HasAVX512VL = isSet(31, ebx7)         // Check presence of AVX512VL - bit 31 of EBX
		X86.HasAVX512BW = isSet(30, ebx7)         // Check presence of AVX512BW - bit 30 of EBX
		X86.HasAVX512DQ = isSet(17, ebx7)         // Check presence of AVX512F - bit 16 of EBX
		X86.HasAVX512IFMA = isSet(21, ebx7)       // Check presence of AVX512IFMA - bit 21 of EBX
		X86.HasAVX512VBMI = isSet(1, ecx7)        // Check presence of AVX512VBMI - bit 1 of ECX
		X86.HasAVX5124VNNIW = isSet(2, edx7)      // Check presence of AVX5124VNNIW - bit 2 of EDX
		X86.HasAVX5124FMAPS = isSet(3, edx7)      // Check presence of AVX5124FMAPS - bit 3 of EDX
		X86.HasAVX512VPOPCNTDQ = isSet(14, ecx7)  // Check presence of AVX512VPOPCNTDQ - bit 14 of ECX
		X86.HasAVX512VPCLMULQDQ = isSet(10, ecx7) // Check presence of VPCLMULQDQ - bit 10 of ECX
		X86.HasAVX512VNNI = isSet(11, ecx7)       // Check presence of AVX512VNNI - bit 11 of ECX
		X86.HasAVX512GFNI = isSet(8, ecx7)        // Check presence of AVX512GFNI - bit 8 of ECX
		X86.HasAVX512VAES = isSet(9, ecx7)        // Check presence of AVX512VAES - bit 9 of ECX
		X86.HasAVX512VBMI2 = isSet(6, ecx7)       // Check presence of AVX512VBMI2 - bit 6 of ECX
		X86.HasAVX512BITALG = isSet(12, ecx7)     // Check presence of AVX512BITALG - bit 12 of ECX
	}

	X86.HasAMXTile = isSet(24, edx7)
	X86.HasAMXInt8 = isSet(25, edx7)
	X86.HasAMXBF16 = isSet(22, edx7)

	// These features depend on the second level of extended features.
	if eax7 >= 1 {
		eax71, _, _, edx71 := cpuid(7, 1)
		if X86.HasAVX512 {
			X86.HasAVX512BF16 = isSet(5, eax71)
		}
		if X86.HasAVX {
			X86.HasAVXIFMA = isSet(23, eax71) // Check presence of AVXIFMA - bit 23 of EAX
			X86.HasAVXVNNI = isSet(4, eax71)
			X86.HasAVXVNNIInt8 = isSet(4, edx71)
		}
	}
}

func isSet(bitpos uint, value uint32) bool {
	return value&(1<<bitpos) != 0
}
