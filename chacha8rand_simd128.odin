package chacha8rand

import "base:intrinsics"

@(private = "file")
u32x4 :: #simd[4]u32

@(private = "file")
S0: u32x4 : {CHACHA_SIGMA_0, CHACHA_SIGMA_0, CHACHA_SIGMA_0, CHACHA_SIGMA_0}
@(private = "file")
S1: u32x4 : {CHACHA_SIGMA_1, CHACHA_SIGMA_1, CHACHA_SIGMA_1, CHACHA_SIGMA_1}
@(private = "file")
S2: u32x4 : {CHACHA_SIGMA_2, CHACHA_SIGMA_2, CHACHA_SIGMA_2, CHACHA_SIGMA_2}
@(private = "file")
S3: u32x4 : {CHACHA_SIGMA_3, CHACHA_SIGMA_3, CHACHA_SIGMA_3, CHACHA_SIGMA_3}

@(private = "file")
_ROT_7L: u32x4 : {7, 7, 7, 7}
@(private = "file")
_ROT_7R: u32x4 : {25, 25, 25, 25}
@(private = "file")
_ROT_12L: u32x4 : {12, 12, 12, 12}
@(private = "file")
_ROT_12R: u32x4 : {20, 20, 20, 20}
@(private = "file")
_ROT_8L: u32x4 : {8, 8, 8, 8}
@(private = "file")
_ROT_8R: u32x4 : {24, 24, 24, 24}
@(private = "file")
_ROT_16: u32x4 : {16, 16, 16, 16}
@(private = "file")
_CTR_INC: u32x4 : {4, 4, 4, 4}

when ODIN_ENDIAN == .Big {
	@(private = "file")
	_byteswap_u32x4 :: #force_inline proc "contextless" (v: u32x4) -> u32x4 {
		u8x16 :: #simd[16]u8
		return(
			transmute(u32x4)simd.shuffle(
				transmute(u8x16)v,
				transmute(u8x16)v,
				3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
			)
		)
	}
}

@(private)
chacha8rand_refill_simd128 :: proc(r: ^Chacha8Rand_State) {
	// Initialize the base state.
	k: [^]u32 = (^u32)(raw_data(r._buf[RNG_OUTPUT_PER_ITER:]))
	when ODIN_ENDIAN == .Little {
		s4_ := k[0]
		s5_ := k[1]
		s6_ := k[2]
		s7_ := k[3]
		s8_ := k[4]
		s9_ := k[5]
		s10_ := k[6]
		s11_ := k[7]
	} else {
		s4_ := intrinsics.byte_swap(k[0])
		s5_ := intrinsics.byte_swap(k[1])
		s6_ := intrinsics.byte_swap(k[2])
		s7_ := intrinsics.byte_swap(k[3])
		s8_ := intrinsics.byte_swap(k[4])
		s9_ := intrinsics.byte_swap(k[5])
		s10_ := intrinsics.byte_swap(k[6])
		s11_ := intrinicss.byte_swap(k[7])
	}

	// 4-lane ChaCha8.
	s4 := u32x4{s4_, s4_, s4_, s4_}
	s5 := u32x4{s5_, s5_, s5_, s5_}
	s6 := u32x4{s6_, s6_, s6_, s6_}
	s7 := u32x4{s7_, s7_, s7_, s7_}
	s8 := u32x4{s8_, s8_, s8_, s8_}
	s9 := u32x4{s9_, s9_, s9_, s9_}
	s10 := u32x4{s10_, s10_, s10_, s10_}
	s11 := u32x4{s11_, s11_, s11_, s11_}
	s12 := u32x4{0, 1, 2, 3}
	s13, s14, s15: u32x4

	dst: [^]u32x4 = (^u32x4)(raw_data(r._buf[:]))

	quarter_round := #force_inline proc "contextless" (a, b, c, d: u32x4) -> (u32x4, u32x4, u32x4, u32x4) {
		a, b, c, d := a, b, c, d

		a = intrinsics.simd_add(a, b)
		d = intrinsics.simd_bit_xor(d, a)
		d = intrinsics.simd_bit_xor(intrinsics.simd_shl(d, _ROT_16), intrinsics.simd_shr(d, _ROT_16))

		c = intrinsics.simd_add(c, d)
		b = intrinsics.simd_bit_xor(b, c)
		b = intrinsics.simd_bit_xor(intrinsics.simd_shl(b, _ROT_12L), intrinsics.simd_shr(b, _ROT_12R))

		a = intrinsics.simd_add(a, b)
		d = intrinsics.simd_bit_xor(d, a)
		d = intrinsics.simd_bit_xor(intrinsics.simd_shl(d, _ROT_8L), intrinsics.simd_shr(d, _ROT_8R))

		c = intrinsics.simd_add(c, d)
		b = intrinsics.simd_bit_xor(b, c)
		b = intrinsics.simd_bit_xor(intrinsics.simd_shl(b, _ROT_7L), intrinsics.simd_shr(b, _ROT_7R))

		return a, b, c, d
	}

	// TODO: Non-intel can do 8 blocks at a time.
	for g := 0; g < 4; g = g + 1 {
		x0, x1, x2, x3 := S0, S1, S2, S3
		x4, x5, x6, x7 := s4, s5, s6, s7
		x8, x9, x10, x11 := s8, s9, s10, s11
		x12, x13, x14, x15 := s12, s13, s14, s15

		for i := CHACHA_ROUNDS; i > 0; i = i - 2 {
			x0, x4, x8, x12 = quarter_round(x0, x4, x8, x12)
			x1, x5, x9, x13 = quarter_round(x1, x5, x9, x13)
			x2, x6, x10, x14 = quarter_round(x2, x6, x10, x14)
			x3, x7, x11, x15 = quarter_round(x3, x7, x11, x15)

			x0, x5, x10, x15 = quarter_round(x0, x5, x10, x15)
			x1, x6, x11, x12 = quarter_round(x1, x6, x11, x12)
			x2, x7, x8, x13 = quarter_round(x2, x7, x8, x13)
			x3, x4, x9, x14 = quarter_round(x3, x4, x9, x14)
		}

		when ODIN_ENDIAN == .Little {
			intrinsics.unaligned_store(&dst[0], x0)
			intrinsics.unaligned_store(&dst[1], x1)
			intrinsics.unaligned_store(&dst[2], x2)
			intrinsics.unaligned_store(&dst[3], x3)
			intrinsics.unaligned_store(&dst[4], intrinsics.simd_add(x4, s4))
			intrinsics.unaligned_store(&dst[5], intrinsics.simd_add(x5, s5))
			intrinsics.unaligned_store(&dst[6], intrinsics.simd_add(x6, s6))
			intrinsics.unaligned_store(&dst[7], intrinsics.simd_add(x7, s7))
			intrinsics.unaligned_store(&dst[8], intrinsics.simd_add(x8, s8))
			intrinsics.unaligned_store(&dst[9], intrinsics.simd_add(x9, s9))
			intrinsics.unaligned_store(&dst[10], intrinsics.simd_add(x10, s10))
			intrinsics.unaligned_store(&dst[11], intrinsics.simd_add(x11, s11))
			intrinsics.unaligned_store(&dst[12], x12)
			intrinsics.unaligned_store(&dst[13], intrinsics.simd_add(x13, s13))
			intrinsics.unaligned_store(&dst[14], intrinsics.simd_add(x14, s14))
			intrinsics.unaligned_store(&dst[15], intrinsics.simd_add(x15, s15))
		} else {
			intrinsics.unaligned_store(&dst[0], _byteswap_u32x4(x0))
			intrinsics.unaligned_store(&dst[1], _byteswap_u32x4(x1))
			intrinsics.unaligned_store(&dst[2], _byteswap_u32x4(x2))
			intrinsics.unaligned_store(&dst[3], _byteswap_u32x4(x3))
			intrinsics.unaligned_store(&dst[4], _byteswap_u32x4(intrinsics.simd_add(x4, s4)))
			intrinsics.unaligned_store(&dst[5], _byteswap_u32x4(intrinsics.simd_add(x5, s5)))
			intrinsics.unaligned_store(&dst[6], _byteswap_u32x4(intrinsics.simd_add(x6, s6)))
			intrinsics.unaligned_store(&dst[7], _byteswap_u32x4(intrinsics.simd_add(x7, s7)))
			intrinsics.unaligned_store(&dst[8], _byteswap_u32x4(intrinsics.simd_add(x8, s8)))
			intrinsics.unaligned_store(&dst[9], _byteswap_u32x4(intrinsics.simd_add(x9, s9)))
			intrinsics.unaligned_store(&dst[10], _byteswap_u32x4(intrinsics.simd_add(x10, s10)))
			intrinsics.unaligned_store(&dst[11], _byteswap_u32x4(intrinsics.simd_add(x11, s11)))
			intrinsics.unaligned_store(&dst[12], _byteswap_u32x4(x12))
			intrinsics.unaligned_store(&dst[13], _byteswap_u32x4(intrinsics.simd_add(x13, s13)))
			intrinsics.unaligned_store(&dst[14], _byteswap_u32x4(intrinsics.simd_add(x14, s14)))
			intrinsics.unaligned_store(&dst[15], _byteswap_u32x4(intrinsics.simd_add(x15, s15)))
		}

		s12 = intrinsics.simd_add(s12, _CTR_INC)

		dst = dst[16:]
	}
}
