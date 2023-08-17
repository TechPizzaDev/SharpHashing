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

using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

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

        private static void pclmulqdq(ref Vector128<byte> xmm, Vector128<byte> m128, byte imm8)
        {
            xmm = Pclmulqdq.CarrylessMultiply(xmm.AsUInt64(), m128.AsUInt64(), imm8).AsByte();
        }

        private static void movdqu(out Vector128<byte> xmm, byte* ptr)
        {
            xmm = Vector128.Load(ptr);
        }

        private static void movdqa(out Vector128<byte> xmm, byte* ptr)
        {
            xmm = Vector128.LoadAligned(ptr);
        }

        private static void movdqa(out Vector128<byte> xmm, ulong e0, ulong e1)
        {
            xmm = Vector128.Create(e0, e1).AsByte();
        }

        private static void movd(out Vector128<byte> xmm, uint value)
        {
            xmm = Vector128.CreateScalar(value).AsByte();
        }

        private static void pslldq(ref Vector128<byte> a, byte b)
        {
            a = Sse2.ShiftLeftLogical128BitLane(a.AsUInt64(), b).AsByte();
        }

        private static void psrldq(ref Vector128<byte> a, byte b)
        {
            a = Sse2.ShiftRightLogical128BitLane(a.AsUInt64(), b).AsByte();
        }

        private static void pxor(ref Vector128<byte> a, Vector128<byte> b)
        {
            a = Sse2.Xor(a, b);
        }

        private static void xorps(ref Vector128<byte> a, Vector128<byte> b)
        {
            a = Sse.Xor(a.AsSingle(), b.AsSingle()).AsByte();
        }

        private static void pshufb(ref Vector128<byte> a, Vector128<byte> b)
        {
            a = Ssse3.Shuffle(a, b);
        }

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
            movdqu(out var data0, rdx + 16 * 0);
            movdqu(out var data1, rdx + 16 * 1);
            movdqu(out var data2, rdx + 16 * 2);
            movdqu(out var data3, rdx + 16 * 3);
            movdqu(out var data4, rdx + 16 * 4);
            movdqu(out var data5, rdx + 16 * 5);
            movdqu(out var data6, rdx + 16 * 6);
            movdqu(out var data7, rdx + 16 * 7);

            pshufb(ref data0, smask);

            // load the initial crc value
            movd(out var eInitialCrc, ecx); // initial crc
            pslldq(ref eInitialCrc, 12); // shift to high order bits

            // XOR the initial_crc value
            pxor(ref data0, eInitialCrc);
            pshufb(ref data1, smask);
            pshufb(ref data2, smask);
            pshufb(ref data3, smask);
            pshufb(ref data4, smask);
            pshufb(ref data5, smask);
            pshufb(ref data6, smask);
            pshufb(ref data7, smask);

            var rk03_04 = Vector128.Create(rk03, rk04).AsByte(); // xmm10 has rk03 and rk04

            // imm value of pclmulqdq instruction will determine which constant to use
            // ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
            // we subtract 256 instead of 128 to save one instruction from the loop
            r8 -= 256;

            // at this section of the code, there is 128*x+y (0<=y<128) bytes of buffer. The _fold_128_B_loop
            // loop will fold 128B at a time until we have 128+y Bytes of buffer

            // fold 128B at a time. This section of the code folds 8 xmm registers in parallel
            do
            {
                // update the buffer pointer
                rdx += 128; // buf += 128;

                movdqu(out var rd0, rdx + 16 * 0);
                movdqu(out var rd1, rdx + 16 * 1);
                pshufb(ref rd0, smask);
                pshufb(ref rd1, smask);
                var d0 = data0;
                var d1 = data1;
                pclmulqdq(ref data0, rk03_04, 0x00);
                pclmulqdq(ref d0, rk03_04, 0x11);
                pclmulqdq(ref data1, rk03_04, 0x00);
                pclmulqdq(ref d1, rk03_04, 0x11);
                pxor(ref data0, rd0);
                xorps(ref data0, d0);
                pxor(ref data1, rd1);
                xorps(ref data1, d1);

                movdqu(out var rd2, rdx + 16 * 2);
                movdqu(out var rd3, rdx + 16 * 3);
                pshufb(ref rd2, smask);
                pshufb(ref rd3, smask);
                var d2 = data2;
                var d3 = data3;
                pclmulqdq(ref data2, rk03_04, 0x00);
                pclmulqdq(ref d2, rk03_04, 0x11);
                pclmulqdq(ref data3, rk03_04, 0x00);
                pclmulqdq(ref d3, rk03_04, 0x11);
                pxor(ref data2, rd2);
                xorps(ref data2, d2);
                pxor(ref data3, rd3);
                xorps(ref data3, d3);

                movdqu(out var rd4, rdx + 16 * 4);
                movdqu(out var rd5, rdx + 16 * 5);
                pshufb(ref rd4, smask);
                pshufb(ref rd5, smask);
                var d4 = data4;
                var d5 = data5;
                pclmulqdq(ref data4, rk03_04, 0x00);
                pclmulqdq(ref d4, rk03_04, 0x11);
                pclmulqdq(ref data5, rk03_04, 0x00);
                pclmulqdq(ref d5, rk03_04, 0x11);
                pxor(ref data4, rd4);
                xorps(ref data4, d4);
                pxor(ref data5, rd5);
                xorps(ref data5, d5);

                movdqu(out var rd6, rdx + 16 * 6);
                movdqu(out var rd7, rdx + 16 * 7);
                pshufb(ref rd6, smask);
                pshufb(ref rd7, smask);
                var d6 = data6;
                var d7 = data7;
                pclmulqdq(ref data6, rk03_04, 0x00);
                pclmulqdq(ref d6, rk03_04, 0x11);
                pclmulqdq(ref data7, rk03_04, 0x00);
                pclmulqdq(ref d7, rk03_04, 0x11);
                pxor(ref data6, rd6);
                xorps(ref data6, d6);
                pxor(ref data7, rd7);
                xorps(ref data7, d7);

                r8 -= 128;
            }
            // check if there is another 128B in the buffer to be able to fold
            while ((long)r8 >= 128);
            // ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

            rdx += 128;
            // at this point, the buffer pointer is pointing at the last y Bytes of the buffer
            // fold the 8 xmm registers to 1 xmm register with different constants

            movdqa(out var rk09_10, rk09, rk10);
            var xmm8 = data0;
            pclmulqdq(ref data0, rk09_10, 0x11);
            pclmulqdq(ref xmm8, rk09_10, 0x00);
            pxor(ref data7, xmm8);
            xorps(ref data7, data0);

            movdqa(out var rk11_12, rk11, rk12);
            xmm8 = data1;
            pclmulqdq(ref data1, rk11_12, 0x11);
            pclmulqdq(ref xmm8, rk11_12, 0x00);
            pxor(ref data7, xmm8);
            xorps(ref data7, data1);

            movdqa(out var rk13_14, rk13, rk14);
            xmm8 = data2;
            pclmulqdq(ref data2, rk13_14, 0x11);
            pclmulqdq(ref xmm8, rk13_14, 0x00);
            pxor(ref data7, xmm8);
            pxor(ref data7, data2);

            movdqa(out var rk15_16, rk15, rk16);
            xmm8 = data3;
            pclmulqdq(ref data3, rk15_16, 0x11);
            pclmulqdq(ref xmm8, rk15_16, 0x00);
            pxor(ref data7, xmm8);
            xorps(ref data7, data3);

            movdqa(out var rk17_18, rk17, rk18);
            xmm8 = data4;
            pclmulqdq(ref data4, rk17_18, 0x11);
            pclmulqdq(ref xmm8, rk17_18, 0x00);
            pxor(ref data7, xmm8);
            pxor(ref data7, data4);

            movdqa(out var rk19_20, rk19, rk20);
            xmm8 = data5;
            pclmulqdq(ref data5, rk19_20, 0x11);
            pclmulqdq(ref xmm8, rk19_20, 0x00);
            pxor(ref data7, xmm8);
            xorps(ref data7, data5);

            movdqa(out var rk01_02, rk01, rk02);
            xmm8 = data6;
            pclmulqdq(ref data6, rk01_02, 0x11);
            pclmulqdq(ref xmm8, rk01_02, 0x00);
            pxor(ref data7, xmm8);
            pxor(ref data7, data6);

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
            do
            {
                xmm8 = data7;
                pclmulqdq(ref data7, rk01_02, 0x11);
                pclmulqdq(ref xmm8, rk01_02, 0x00);
                pxor(ref data7, xmm8);
                movdqu(out var dataTmp, rdx);
                pshufb(ref dataTmp, smask);
                pxor(ref data7, dataTmp);
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
                movdqu(out var shufTab2, (byte*)&pshufb_shf_table + 16 - r8);

                // shift xmm2 to the left by r8 bytes
                var tmp = data7;
                pshufb(ref tmp, shufTab2);

                // shift xmm7 to the right by 16-r8 byte
                pxor(ref shufTab2, mask1);
                pshufb(ref data7, shufTab2);

                movdqu(out var rdr, rdx - 16 + r8);
                pshufb(ref rdr, smask);

                // fold 16 Bytes
                var x2 = Sse41.BlendVariable(rdr, tmp, shufTab2);
                var x1 = data7;
                pclmulqdq(ref data7, rk01_02, 0x11);
                pclmulqdq(ref x1, rk01_02, 0x00);
                pxor(ref data7, x1);
                pxor(ref data7, x2);
            }

        _128_done:
            {
                // compute crc of a 128-bit value
                movdqa(out var rk05_06, rk05, rk06); // rk05 and rk06 in xmm10
                var tmp = data7;

                // 64b fold
                pclmulqdq(ref data7, rk05_06, 0x01);
                pslldq(ref tmp, 8);
                pxor(ref data7, tmp);

                // 32b fold
                var mask2 = Vector128.Create(0x_FFFFFFFF_FFFFFFFF, 0x_00000000_FFFFFFFF).AsByte();
                tmp = Sse2.And(data7, mask2);

                psrldq(ref data7, 12);
                pclmulqdq(ref data7, rk05_06, 0x10);
                pxor(ref data7, tmp);
            }

            uint eax;
        // barrett reduction
        _barrett:
            {
                movdqa(out var rk07_08, rk07, rk08); // rk07 and rk08 in xmm10
                var tmp = data7;
                pclmulqdq(ref data7, rk07_08, 0x01);
                pslldq(ref data7, 4);
                pclmulqdq(ref data7, rk07_08, 0x11);
                pslldq(ref data7, 4);
                pxor(ref data7, tmp);
                eax = Sse41.Extract(data7.AsUInt32(), 1);
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

            // if there is, load the constants
            movdqa(out rk01_02, rk01, rk02); // rk01 and rk02 in xmm10

            movd(out var initialCrc, ecx); // get the initial crc value
            pslldq(ref initialCrc, 12); // align it to its correct place
            movdqu(out data7, rdx); // load the plaintext
            pshufb(ref data7, smask);
            pxor(ref data7, initialCrc);

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

                movd(out initialCrc, ecx); // get the initial crc value
                pslldq(ref initialCrc, 12); // align it to its correct place

                if (r8 == 16)
                {
                    goto _exact_16_left;
                }
                if ((long)r8 < 16)
                {
                    goto _less_than_16_left;
                }

                movdqu(out data7, rdx); // load the plaintext
                pshufb(ref data7, smask);
                pxor(ref data7, initialCrc); // xor the initial crc value
                rdx += 16;
                r8 -= 16;
                movdqa(out rk01_02, rk01, rk02); // rk01 and rk02 in xmm10
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
                movdqa(out data7, (byte*)&rsp);
                pshufb(ref data7, smask);
                pxor(ref data7, initialCrc); // xor the initial crc value

                movdqu(out var shufTab, (byte*)&pshufb_shf_table + 16 - r9);
                pxor(ref shufTab, mask1.AsByte());

                pshufb(ref data7, shufTab);
                goto _128_done;
            }

        //align 16
        _exact_16_left:
            {
                movdqu(out data7, rdx);
                pshufb(ref data7, smask);
                pxor(ref data7, initialCrc); // xor the initial crc value

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

                movdqa(out data7, (byte*)&rsp);
                pshufb(ref data7, smask);
                pxor(ref data7, initialCrc); // xor the initial crc value

                psrldq(ref data7, 5);

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

                movdqa(out data7, (byte*)&rsp);
                pshufb(ref data7, smask);
                pxor(ref data7, initialCrc); // xor the initial crc value

                psrldq(ref data7, 6);

                goto _barrett;
            }

        _only_less_than_2:
            {
                // load 1 Byte
                r11[0] = rdx[0];

                movdqa(out data7, (byte*)&rsp);
                pshufb(ref data7, smask);
                pxor(ref data7, initialCrc); // xor the initial crc value

                psrldq(ref data7, 7);

                goto _barrett;
            }
        }
    }
}
