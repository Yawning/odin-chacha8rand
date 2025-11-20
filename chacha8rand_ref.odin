package chacha8rand

import "base:intrinsics"

@(private)
chacha8rand_refill_ref :: proc(r: ^Chacha8Rand_State) {
	// Initialize the base state.
	k: [^]u32 = (^u32)(raw_data(r._buf[RNG_OUTPUT_PER_ITER:]))
	when ODIN_ENDIAN == .Little {
		s4 := k[0]
		s5 := k[1]
		s6 := k[2]
		s7 := k[3]
		s8 := k[4]
		s9 := k[5]
		s10 := k[6]
		s11 := k[7]
	} else {
		s4 := intrinsics.byte_swap(k[0])
		s5 := intrinsics.byte_swap(k[1])
		s6 := intrinsics.byte_swap(k[2])
		s7 := intrinsics.byte_swap(k[3])
		s8 := intrinsics.byte_swap(k[4])
		s9 := intrinsics.byte_swap(k[5])
		s10 := intrinsics.byte_swap(k[6])
		s11 := intrinicss.byte_swap(k[7])
	}
	s12: u32           // Counter starts at 0.
	s13, s14, s15: u32 // IV of all 0s.

	dst: [^]u32 = (^u32)(raw_data(r._buf[:]))

	// 4 groups
	for g := 0; g < 4; g = g + 1 {
		// 4 blocks per group
		for n := 0; n < 4; n = n + 1 {
			// TODO/perf: Precomputation trickery
			x0, x1, x2, x3 := CHACHA_SIGMA_0, CHACHA_SIGMA_1, CHACHA_SIGMA_2, CHACHA_SIGMA_3
			x4, x5, x6, x7 := s4, s5, s6, s7
			x8, x9, x10, x11 := s8, s9, s10, s11
			x12, x13, x14, x15 := s12, s13, s14, s15

			// 8 rounds, 2 rounds at a time
			for i := CHACHA_ROUNDS; i > 0; i = i - 2 {
				// Even when forcing inlining manually inlining all of
				// these is decently faster.

				// quarterround(x, 0, 4, 8, 12)
				x0 += x4
				x12 ~= x0
				x12 = rotl(x12, 16)
				x8 += x12
				x4 ~= x8
				x4 = rotl(x4, 12)
				x0 += x4
				x12 ~= x0
				x12 = rotl(x12, 8)
				x8 += x12
				x4 ~= x8
				x4 = rotl(x4, 7)

				// quarterround(x, 1, 5, 9, 13)
				x1 += x5
				x13 ~= x1
				x13 = rotl(x13, 16)
				x9 += x13
				x5 ~= x9
				x5 = rotl(x5, 12)
				x1 += x5
				x13 ~= x1
				x13 = rotl(x13, 8)
				x9 += x13
				x5 ~= x9
				x5 = rotl(x5, 7)

				// quarterround(x, 2, 6, 10, 14)
				x2 += x6
				x14 ~= x2
				x14 = rotl(x14, 16)
				x10 += x14
				x6 ~= x10
				x6 = rotl(x6, 12)
				x2 += x6
				x14 ~= x2
				x14 = rotl(x14, 8)
				x10 += x14
				x6 ~= x10
				x6 = rotl(x6, 7)

				// quarterround(x, 3, 7, 11, 15)
				x3 += x7
				x15 ~= x3
				x15 = rotl(x15, 16)
				x11 += x15
				x7 ~= x11
				x7 = rotl(x7, 12)
				x3 += x7
				x15 ~= x3
				x15 = rotl(x15, 8)
				x11 += x15
				x7 ~= x11
				x7 = rotl(x7, 7)

				// quarterround(x, 0, 5, 10, 15)
				x0 += x5
				x15 ~= x0
				x15 = rotl(x15, 16)
				x10 += x15
				x5 ~= x10
				x5 = rotl(x5, 12)
				x0 += x5
				x15 ~= x0
				x15 = rotl(x15, 8)
				x10 += x15
				x5 ~= x10
				x5 = rotl(x5, 7)

				// quarterround(x, 1, 6, 11, 12)
				x1 += x6
				x12 ~= x1
				x12 = rotl(x12, 16)
				x11 += x12
				x6 ~= x11
				x6 = rotl(x6, 12)
				x1 += x6
				x12 ~= x1
				x12 = rotl(x12, 8)
				x11 += x12
				x6 ~= x11
				x6 = rotl(x6, 7)

				// quarterround(x, 2, 7, 8, 13)
				x2 += x7
				x13 ~= x2
				x13 = rotl(x13, 16)
				x8 += x13
				x7 ~= x8
				x7 = rotl(x7, 12)
				x2 += x7
				x13 ~= x2
				x13 = rotl(x13, 8)
				x8 += x13
				x7 ~= x8
				x7 = rotl(x7, 7)

				// quarterround(x, 3, 4, 9, 14)
				x3 += x4
				x14 ~= x3
				x14 = rotl(x14, 16)
				x9 += x14
				x4 ~= x9
				x4 = rotl(x4, 12)
				x3 += x4
				x14 ~= x3
				x14 = rotl(x14, 8)
				x9 += x14
				x4 ~= x9
				x4 = rotl(x4, 7)
			}

			// Interleave 4 blocks
			// NB: The additions of sigma and the counter are omitted
			STRIDE :: 4
			d_ := dst[n:]
			when ODIN_ENDIAN == .Little {
				d_[STRIDE*0] = x0
				d_[STRIDE*1] = x1
				d_[STRIDE*2] = x2
				d_[STRIDE*3] = x3
				d_[STRIDE*4] = x4 + s4
				d_[STRIDE*5] = x5 + s5
				d_[STRIDE*6] = x6 + s6
				d_[STRIDE*7] = x7 + s7
				d_[STRIDE*8] = x8 + s8
				d_[STRIDE*9] = x9 + s9
				d_[STRIDE*10] = x10 + s10
				d_[STRIDE*11] = x11 + s11
				d_[STRIDE*12] = x12
				d_[STRIDE*13] = x13 + s13
				d_[STRIDE*14] = x14 + s14
				d_[STRIDE*15] = x15 + s15
			} else {
				d_[STRIDE*0] = intrinsics.byte_swap(x0)
				d_[STRIDE*1] = intrinsics.byte_swap(x1)
				d_[STRIDE*2] = intrinsics.byte_swap(x2)
				d_[STRIDE*3] = intrinsics.byte_swap(x3)
				d_[STRIDE*4] = intrinsics.byte_swap(x4 + s4)
				d_[STRIDE*5] = intrinsics.byte_swap(x5 + s5)
				d_[STRIDE*6] = intrinsics.byte_swap(x6 + s6)
				d_[STRIDE*7] = intrinsics.byte_swap(x7 + s7)
				d_[STRIDE*8] = intrinsics.byte_swap(x8 + s8)
				d_[STRIDE*9] = intrinsics.byte_swap(x9 + s9)
				d_[STRIDE*10] = intrinsics.byte_swap(x10 + s10)
				d_[STRIDE*11] = intrinsics.byte_swap(x11 + s11)
				d_[STRIDE*12] = intrinsics.byte_swap(x12)
				d_[STRIDE*13] = intrinsics.byte_swap(x13 + s13)
				d_[STRIDE*14] = intrinsics.byte_swap(x14 + s14)
				d_[STRIDE*15] = intrinsics.byte_swap(x15 + s15)
			}

			s12 = s12 + 1 // Increment the counter
		}

		dst = dst[16*4:]
	}
}

// This replicates `rotate_left32` from `core:math/bits`, under the
// assumption that this will live in `base:runtime`.
@(require_results, private = "file")
rotl :: #force_inline proc "contextless" (x: u32, k: int) -> u32 {
	n :: 32
	s := uint(k) & (n-1)
	return x << s | x >> (n-s)
}
