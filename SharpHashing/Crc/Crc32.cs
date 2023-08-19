//        title   crc32fa
//;       page    80,132
//;-----------------------------------------------------------------------;
//;       crc32fa.asm     fast 32 bit crc                                 ;
//;-----------------------------------------------------------------------;
//;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
//;  Copyright(c) 2011-2015 Intel Corporation All rights reserved.
//;
//;  Redistribution and use in source and binary forms, with or without
//;  modification, are permitted provided that the following conditions
//;  are met:
//;    * Redistributions of source code must retain the above copyright
//;      notice, this list of conditions and the following disclaimer.
//;    * Redistributions in binary form must reproduce the above copyright
//;      notice, this list of conditions and the following disclaimer in
//;      the documentation and/or other materials provided with the
//;      distribution.
//;    * Neither the name of Intel Corporation nor the names of its
//;      contributors may be used to endorse or promote products derived
//;      from this software without specific prior written permission.
//;
//;  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//;  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//;  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//;  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//;  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//;  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
//;  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//;  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//;  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//;  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//;  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace SharpHashing.Crc
{
    public static unsafe class Crc32
    {
        const ulong rk01 = 0x_f200aa66_00000000; // 2^(32* 3) mod P(x) << 32
        const ulong rk02 = 0x_17d3315d_00000000; // 2^(32* 5) mod P(x) << 32
        const ulong rk03 = 0x_022ffca5_00000000; // 2^(32*31) mod P(x) << 32
        const ulong rk04 = 0x_9d9ee22f_00000000; // 2^(32*33) mod P(x) << 32
        const ulong rk05 = 0x_f200aa66_00000000; // 2^(32* 3) mod P(x) << 32
        const ulong rk06 = 0x_490d678d_00000000; // 2^(32* 2) mod P(x) << 32
        const ulong rk07 = 0x_00000001_04d101df; // floor(2^64/P(x))
        const ulong rk08 = 0x_00000001_04c11db7; // P(x)
        const ulong rk09 = 0x_6ac7e7d7_00000000; // 2^(32*27) mod P(x) << 32
        const ulong rk10 = 0x_fcd922af_00000000; // 2^(32*29) mod P(x) << 32
        const ulong rk11 = 0x_34e45a63_00000000; // 2^(32*23) mod P(x) << 32
        const ulong rk12 = 0x_8762c1f6_00000000; // 2^(32*25) mod P(x) << 32
        const ulong rk13 = 0x_5395a0ea_00000000; // 2^(32*19) mod P(x) << 32
        const ulong rk14 = 0x_54f2d5c7_00000000; // 2^(32*21) mod P(x) << 32
        const ulong rk15 = 0x_d3504ec7_00000000; // 2^(32*15) mod P(x) << 32
        const ulong rk16 = 0x_57a84455_00000000; // 2^(32*17) mod P(x) << 32
        const ulong rk17 = 0x_c053585d_00000000; // 2^(32*11) mod P(x) << 32
        const ulong rk18 = 0x_766f1b78_00000000; // 2^(32*13) mod P(x) << 32
        const ulong rk19 = 0x_cd8c54b5_00000000; // 2^(32* 7) mod P(x) << 32
        const ulong rk20 = 0x_ab40b71e_00000000; // 2^(32* 9) mod P(x) << 32

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static uint crc32f(uint ecx, byte* rdx, ulong r8)
        {
            var mask1 = Vector128.Create(0x_80808080_80808080, 0x_80808080_80808080).AsByte();

            var smask = Vector128.Create(0x_08090A0B_0C0D0E0F, 0x_00010203_04050607).AsByte();  // byte reflect mask

            // use these values for shift constants for the pshufb(ref  instruction
            // different alignments result in values as shown:
            //       dq 0x_88878685_84838281, 0x_008f8e8d_8c8b8a89 ; shl 15 (16-1) / shr1
            //       dq 0x_89888786_85848382, 0x_01008f8e_8d8c8b8a ; shl 14 (16-3) / shr2
            //       dq 0x_8a898887_86858483, 0x_0201008f_8e8d8c8b ; shl 13 (16-4) / shr3
            //       dq 0x_8b8a8988_87868584, 0x_03020100_8f8e8d8c ; shl 12 (16-4) / shr4
            //       dq 0x_8c8b8a89_88878685, 0x_04030201_008f8e8d ; shl 11 (16-5) / shr5
            //       dq 0x_8d8c8b8a_89888786, 0x_05040302_01008f8e ; shl 10 (16-6) / shr6
            //       dq 0x_8e8d8c8b_8a898887, 0x_06050403_0201008f ; shl 9  (16-7) / shr7
            //       dq 0x_8f8e8d8c_8b8a8988, 0x_07060504_03020100 ; shl 8  (16-8) / shr8
            //       dq 0x_008f8e8d_8c8b8a89, 0x_08070605_04030201 ; shl 7  (16-9) / shr9
            //       dq 0x_01008f8e_8d8c8b8a, 0x_09080706_05040302 ; shl 6  (16-10) / shr10
            //       dq 0x_0201008f_8e8d8c8b, 0x_0a090807_06050403 ; shl 5  (16-11) / shr11
            //       dq 0x_03020100_8f8e8d8c, 0x_0b0a0908_07060504 ; shl 4  (16-12) / shr12
            //       dq 0x_04030201_008f8e8d, 0x_0c0b0a09_08070605 ; shl 3  (16-13) / shr13
            //       dq 0x_05040302_01008f8e, 0x_0d0c0b0a_09080706 ; shl 2  (16-14) / shr14
            //       dq 0x_06050403_0201008f, 0x_0e0d0c0b_0a090807 ; shl 1  (16-15) / shr15

            var pshufb_shf_table = (
                 Vector128.Create(0x_87868584_83828100U, 0x_8f8e8d8c_8b8a8988U),
                 Vector128.Create(0x_07060504_03020100U, 0x_0f0e0d0c_0b0a0908U));

            // check if smaller than 256
            if ((long)r8 < 256)
            {
                // for sizes less than 256, we can't fold 128B at a time...
                goto _less_than_256;
            }

            // receive the initial 128B data, xor the initial crc value
            var data0 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 0), smask).AsUInt64();
            var data1 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 1), smask).AsUInt64();
            var data2 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 2), smask).AsUInt64();
            var data3 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 3), smask).AsUInt64();
            var data4 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 4), smask).AsUInt64();
            var data5 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 5), smask).AsUInt64();
            var data6 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 6), smask).AsUInt64();
            var data7 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 7), smask).AsUInt64();

            // load the initial crc value
            var eInitialCrc = Vector128.CreateScalar(ecx).AsUInt64(); // initial crc
            eInitialCrc = VectorHelper.ShiftLeftInVector(eInitialCrc, 12); // shift to high order bits

            // XOR the initial_crc value
            data0 ^= eInitialCrc;

            // imm value of pclmulqdq instruction will determine which constant to use
            // ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
            // we subtract 256 instead of 128 to save one instruction from the loop
            r8 -= 256;

            var rk03_04 = Vector128.Create(rk03, rk04); // xmm10 has rk03 and rk04

            // at this section of the code, there is 128*x+y (0<=y<128) bytes of buffer. The _fold_128_B_loop
            // loop will fold 128B at a time until we have 128+y Bytes of buffer

            // fold 128B at a time. This section of the code folds 8 xmm registers in parallel
            do
            {
                // update the buffer pointer
                rdx += 128; // buf += 128;

                var rd0 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 0), smask).AsUInt64();
                var rd1 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 1), smask).AsUInt64();
                data0 = VectorHelper.FoldPolynomialPair(rd0, data0, rk03_04);
                data1 = VectorHelper.FoldPolynomialPair(rd1, data1, rk03_04);

                var rd2 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 2), smask).AsUInt64();
                var rd3 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 3), smask).AsUInt64();
                data2 = VectorHelper.FoldPolynomialPair(rd2, data2, rk03_04);
                data3 = VectorHelper.FoldPolynomialPair(rd3, data3, rk03_04);

                var rd4 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 4), smask).AsUInt64();
                var rd5 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 5), smask).AsUInt64();
                data4 = VectorHelper.FoldPolynomialPair(rd4, data4, rk03_04);
                data5 = VectorHelper.FoldPolynomialPair(rd5, data5, rk03_04);

                var rd6 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 6), smask).AsUInt64();
                var rd7 = VectorHelper.Shuffle(Vector128.Load(rdx + 16 * 7), smask).AsUInt64();
                data6 = VectorHelper.FoldPolynomialPair(rd6, data6, rk03_04);
                data7 = VectorHelper.FoldPolynomialPair(rd7, data7, rk03_04);

                r8 -= 128;
            }
            // check if there is another 128B in the buffer to be able to fold
            while ((long)r8 >= 128);
            // ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

            rdx += 128;
            // at this point, the buffer pointer is pointing at the last y Bytes of the buffer
            // fold the 8 xmm registers to 1 xmm register with different constants

            data7 = VectorHelper.FoldPolynomialPair(data7, data0, Vector128.Create(rk09, rk10));
            data7 = VectorHelper.FoldPolynomialPair(data7, data1, Vector128.Create(rk11, rk12));
            data7 = VectorHelper.FoldPolynomialPair(data7, data2, Vector128.Create(rk13, rk14));
            data7 = VectorHelper.FoldPolynomialPair(data7, data3, Vector128.Create(rk15, rk16));
            data7 = VectorHelper.FoldPolynomialPair(data7, data4, Vector128.Create(rk17, rk18));
            data7 = VectorHelper.FoldPolynomialPair(data7, data5, Vector128.Create(rk19, rk20));
            data7 = VectorHelper.FoldPolynomialPair(data7, data6, Vector128.Create(rk01, rk02));

            // instead of 128, we add 112 to the loop counter to save 1 instruction from the loop
            // instead of a cmp instruction, we use the negative flag with the jl instruction
            r8 += 128 - 16;
            if ((long)r8 < 0)
            {
                goto _final_reduction_for_128;
            }

        // now we have 16+y bytes left to reduce. 16 Bytes is in register xmm7 and the rest is in memory
        // we can fold 16 bytes at a time if y>=16
        // continue folding 16B at a time

        _16B_reduction_loop:
            var rk01_02 = Vector128.Create(rk01, rk02);
            do
            {
                var data = VectorHelper.Shuffle(Vector128.Load(rdx), smask).AsUInt64();
                data7 = VectorHelper.FoldPolynomialPair(data, data7, rk01_02);

                rdx += 16;
                r8 -= 16;
            }
            // instead of a cmp instruction, we utilize the flags with the jge instruction
            // equivalent of: cmp r8, 16-16
            // check if there is any more 16B in the buffer to be able to fold
            while ((long)r8 >= 0);

        // now we have 16+z bytes left to reduce, where 0<= z < 16.
        // first, we reduce the data in the xmm7 register

        _final_reduction_for_128:
            // check if any more data to fold. If not, compute the CRC of the final 128 bits
            r8 += 16;
            if (r8 == 0)
            {
                goto _128_done;
            }

        // here we are getting data that is less than 16 bytes.
        // since we know that there was data before the pointer, we can offset the input pointer before the actual point, to receive exactly 16 bytes.
        // after that the registers need to be adjusted.
        _get_last_two_xmms:
            {
                // get rid of the extra data that was loaded before
                // load the shift constant
                var shufTab2 = Vector128.Load((byte*)&pshufb_shf_table + 16 - r8);

                // shift xmm2 to the left by r8 bytes
                var tmp = VectorHelper.Shuffle(data7.AsByte(), shufTab2);

                // shift xmm7 to the right by 16-r8 byte
                shufTab2 ^= mask1;
                data7 = VectorHelper.Shuffle(data7.AsByte(), shufTab2).AsUInt64();

                var rdr = VectorHelper.Shuffle(Vector128.Load(rdx - 16 + r8), smask);

                // fold 16 Bytes
                var x2 = VectorHelper.BlendVariable(rdr, tmp, shufTab2).AsUInt64();
                data7 = VectorHelper.FoldPolynomialPair(x2, data7, Vector128.Create(rk01, rk02));
            }

        _128_done:
            {
                // compute crc of a 128-bit value
                var rk05_06 = Vector128.Create(rk05, rk06); // rk05 and rk06 in xmm10
                var tmp = data7;

                // 64b fold
                data7 = VectorHelper.CarrylessMultiplyLeftUpperRightLower(data7, rk05_06);
                tmp = VectorHelper.ShiftLeftInVector(tmp, 8);
                data7 ^= tmp;

                // 32b fold
                var mask2 = Vector128.Create(0x_FFFFFFFF_FFFFFFFF, 0x_00000000_FFFFFFFF);
                tmp = data7 & mask2;

                data7 = VectorHelper.ShiftRightInVector(data7, 12);
                data7 = VectorHelper.CarrylessMultiplyLeftLowerRightUpper(data7, rk05_06);
                data7 ^= tmp;
            }

            uint eax;
        // barrett reduction
        _barrett:
            {
                var rk07_08 = Vector128.Create(rk07, rk08); // rk07 and rk08 in xmm10
                var tmp = data7;
                data7 = VectorHelper.CarrylessMultiplyLeftUpperRightLower(data7, rk07_08);
                data7 = VectorHelper.ShiftLeftInVector(data7, 4);
                data7 = VectorHelper.CarrylessMultiplyUpper(data7, rk07_08);
                data7 = VectorHelper.ShiftLeftInVector(data7, 4);
                data7 ^= tmp;
                eax = data7.AsUInt32().GetElement(1);
            }

        _cleanup:
            return eax;

        //align 16
        _less_than_256:
            // check if there is enough buffer to be able to fold 16B at a time
            if ((long)r8 < 32)
            {
                goto _less_than_32;
            }

            var initialCrc = Vector128.CreateScalar(ecx).AsUInt64(); // get the initial crc value
            initialCrc = VectorHelper.ShiftLeftInVector(initialCrc, 12); // align it to its correct place
            data7 = VectorHelper.Shuffle(Vector128.Load(rdx), smask).AsUInt64(); // load the plaintext
            data7 ^= initialCrc;

            // update the buffer pointer
            rdx += 16;

            // update the counter. subtract 32 instead of 16 to save one instruction from the loop
            r8 -= 32;
            goto _16B_reduction_loop;

        // align 16
        _less_than_32:
            {
                // mov initial crc to the return value. this is necessary for zero-length buffers.
                eax = ecx;
                if (r8 == 0)
                {
                    goto _cleanup;
                }

                initialCrc = Vector128.CreateScalar(ecx).AsUInt64(); // get the initial crc value
                initialCrc = VectorHelper.ShiftLeftInVector(initialCrc, 12); // align it to its correct place

                if (r8 == 16)
                {
                    goto _exact_16_left;
                }
                if ((long)r8 < 16)
                {
                    goto _less_than_16_left;
                }

                data7 = VectorHelper.Shuffle(Vector128.Load(rdx), smask).AsUInt64(); // load the plaintext
                data7 ^= initialCrc; // xor the initial crc value
                rdx += 16;
                r8 -= 16;

                goto _get_last_two_xmms;
            }

        // align 16
        _less_than_16_left:
            // use stack space to load data less than 16 bytes, zero-out the 16B in memory first.
            Vector128<byte> rsp = Vector128<byte>.Zero;
            byte* r11 = (byte*)&rsp;

            if ((long)r8 < 4)
            {
                goto _only_less_than_4;
            }

            // backup the counter value
            ulong r9 = r8;
            if ((long)r8 < 8)
            {
                goto _less_than_8_left;
            }

            // load 8 Bytes
            *(ulong*)r11 = *(ulong*)rdx;
            r11 += 8;
            r8 -= 8;
            rdx += 8;

        _less_than_8_left:
            {
                if ((long)r8 < 4)
                {
                    goto _less_than_4_left;
                }

                // load 4 Bytes
                *(uint*)r11 = *(uint*)rdx;
                r11 += 4;
                r8 -= 4;
                rdx += 4;
            }

        _less_than_4_left:
            {
                if ((long)r8 < 2)
                {
                    goto _less_than_2_left;
                }

                // load 2 Bytes
                *(ushort*)r11 = *(ushort*)rdx;
                r11 += 2;
                r8 -= 2;
                rdx += 2;
            }

        _less_than_2_left:
            {
                if ((long)r8 < 1)
                {
                    goto _zero_left;
                }

                // load 1 Byte
                r11[0] = rdx[0];
            }

        _zero_left:
            {
                data7 = VectorHelper.Shuffle(rsp, smask).AsUInt64();
                data7 ^= initialCrc; // xor the initial crc value

                var shufTab = Vector128.Load((byte*)&pshufb_shf_table + 16 - r9);
                var shufMask = shufTab ^ mask1;
                data7 = VectorHelper.Shuffle(data7.AsByte(), shufMask).AsUInt64();

                goto _128_done;
            }

        //align 16
        _exact_16_left:
            {
                data7 = VectorHelper.Shuffle(Vector128.Load(rdx), smask).AsUInt64();
                data7 ^= initialCrc; // xor the initial crc value

                goto _128_done;
            }

        _only_less_than_4:
            {
                if ((long)r8 < 3)
                {
                    goto _only_less_than_3;
                }

                // load 3 Bytes
                r11[0] = rdx[0];
                r11[1] = rdx[1];
                r11[2] = rdx[2];

                data7 = VectorHelper.Shuffle(rsp, smask).AsUInt64();
                data7 ^= initialCrc; // xor the initial crc value

                data7 = VectorHelper.ShiftRightInVector(data7, 5);

                goto _barrett;
            }

        _only_less_than_3:
            {
                if ((long)r8 < 2)
                {
                    goto _only_less_than_2;
                }

                // load 2 Bytes
                r11[0] = rdx[0];
                r11[1] = rdx[1];

                data7 = VectorHelper.Shuffle(rsp, smask).AsUInt64();
                data7 ^= initialCrc; // xor the initial crc value

                data7 = VectorHelper.ShiftRightInVector(data7, 6);

                goto _barrett;
            }

        _only_less_than_2:
            {
                // load 1 Byte
                r11[0] = rdx[0];

                data7 = VectorHelper.Shuffle(rsp, smask).AsUInt64();
                data7 ^= initialCrc; // xor the initial crc value

                data7 = VectorHelper.ShiftRightInVector(data7, 7);

                goto _barrett;
            }
        }
    }
}
