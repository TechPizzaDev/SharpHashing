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
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace SharpHashing.Crc
{
    public static unsafe class Crc32
    {
        static readonly ulong rk01 = 0x_f200aa66_00000000; // 2^(32* 3) mod P(x) << 32
        static readonly ulong rk02 = 0x_17d3315d_00000000; // 2^(32* 5) mod P(x) << 32
        static readonly ulong rk03 = 0x_022ffca5_00000000; // 2^(32*31) mod P(x) << 32
        static readonly ulong rk04 = 0x_9d9ee22f_00000000; // 2^(32*33) mod P(x) << 32
        static readonly ulong rk05 = 0x_f200aa66_00000000; // 2^(32* 3) mod P(x) << 32
        static readonly ulong rk06 = 0x_490d678d_00000000; // 2^(32* 2) mod P(x) << 32
        static readonly ulong rk07 = 0x_00000001_04d101df; // floor(2^64/P(x))
        static readonly ulong rk08 = 0x_00000001_04c11db7; // P(x)
        static readonly ulong rk09 = 0x_6ac7e7d7_00000000; // 2^(32*27) mod P(x) << 32
        static readonly ulong rk10 = 0x_fcd922af_00000000; // 2^(32*29) mod P(x) << 32
        static readonly ulong rk11 = 0x_34e45a63_00000000; // 2^(32*23) mod P(x) << 32
        static readonly ulong rk12 = 0x_8762c1f6_00000000; // 2^(32*25) mod P(x) << 32
        static readonly ulong rk13 = 0x_5395a0ea_00000000; // 2^(32*19) mod P(x) << 32
        static readonly ulong rk14 = 0x_54f2d5c7_00000000; // 2^(32*21) mod P(x) << 32
        static readonly ulong rk15 = 0x_d3504ec7_00000000; // 2^(32*15) mod P(x) << 32
        static readonly ulong rk16 = 0x_57a84455_00000000; // 2^(32*17) mod P(x) << 32
        static readonly ulong rk17 = 0x_c053585d_00000000; // 2^(32*11) mod P(x) << 32
        static readonly ulong rk18 = 0x_766f1b78_00000000; // 2^(32*13) mod P(x) << 32
        static readonly ulong rk19 = 0x_cd8c54b5_00000000; // 2^(32* 7) mod P(x) << 32
        static readonly ulong rk20 = 0x_ab40b71e_00000000; // 2^(32* 9) mod P(x) << 32

        static readonly Vector128<ulong> mask1 = Vector128.Create(0x_80808080_80808080, 0x_80808080_80808080);
        static readonly Vector128<ulong> mask2 = Vector128.Create(0x_FFFFFFFF_FFFFFFFF, 0x_00000000_FFFFFFFF);

        static readonly Vector128<ulong> smask = Vector128.Create(0x_08090A0B_0C0D0E0F, 0x_00010203_04050607).AsUInt64();

        static readonly Vector128<ulong>* pshufb_shf_table;

        static Crc32()
        {
            pshufb_shf_table = (Vector128<ulong>*)NativeMemory.AlignedAlloc((nuint)Unsafe.SizeOf<Vector128<ulong>>() * 2, 16);

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

            pshufb_shf_table[0] = Vector128.Create(0x_87868584_83828100, 0x_8f8e8d8c_8b8a8988).AsUInt64();
            pshufb_shf_table[1] = Vector128.Create(0x_07060504_03020100, 0x_0f0e0d0c_0b0a0908).AsUInt64();
        }

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
            // check if smaller than 256
            if ((long)r8 < 256)
            {
                // for sizes less than 256, we can't fold 128B at a time...
                goto _less_than_256;
            }

            Vector128<byte>
                xmm0,
                xmm1,
                xmm2,
                xmm3,
                xmm4,
                xmm5,
                xmm6,
                xmm7,
                xmm8,
                xmm9,
                xmm10,
                xmm11,
                xmm12,
                xmm13;

            // receive the initial 128B data, xor the initial crc value
            movdqu(out xmm0, rdx + 16 * 0);
            movdqu(out xmm1, rdx + 16 * 1);
            movdqu(out xmm2, rdx + 16 * 2);
            movdqu(out xmm3, rdx + 16 * 3);
            movdqu(out xmm4, rdx + 16 * 4);
            movdqu(out xmm5, rdx + 16 * 5);
            movdqu(out xmm6, rdx + 16 * 6);
            movdqu(out xmm7, rdx + 16 * 7);

            xmm11 = smask.AsByte(); // byte reflect mask
            pshufb(ref xmm0, xmm11);

            // load the initial crc value
            movd(out xmm10, ecx); // initial crc
            pslldq(ref xmm10, 12); // shift to high order bits

            // XOR the initial_crc value
            pxor(ref xmm0, xmm10);
            pshufb(ref xmm1, xmm11);
            pshufb(ref xmm2, xmm11);
            pshufb(ref xmm3, xmm11);
            pshufb(ref xmm4, xmm11);
            pshufb(ref xmm5, xmm11);
            pshufb(ref xmm6, xmm11);
            pshufb(ref xmm7, xmm11);

            xmm10 = Vector128.Create(rk03, rk04).AsByte(); // xmm10 has rk03 and rk04

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

                movdqu(out xmm9, rdx + 16 * 0);
                movdqu(out xmm12, rdx + 16 * 1);
                pshufb(ref xmm9, xmm11);
                pshufb(ref xmm12, xmm11);
                xmm8 = xmm0;
                xmm13 = xmm1;
                pclmulqdq(ref xmm0, xmm10, 0x00);
                pclmulqdq(ref xmm8, xmm10, 0x11);
                pclmulqdq(ref xmm1, xmm10, 0x00);
                pclmulqdq(ref xmm13, xmm10, 0x11);
                pxor(ref xmm0, xmm9);
                xorps(ref xmm0, xmm8);
                pxor(ref xmm1, xmm12);
                xorps(ref xmm1, xmm13);

                movdqu(out xmm9, rdx + 16 * 2);
                movdqu(out xmm12, rdx + 16 * 3);
                pshufb(ref xmm9, xmm11);
                pshufb(ref xmm12, xmm11);
                xmm8 = xmm2;
                xmm13 = xmm3;
                pclmulqdq(ref xmm2, xmm10, 0x00);
                pclmulqdq(ref xmm8, xmm10, 0x11);
                pclmulqdq(ref xmm3, xmm10, 0x00);
                pclmulqdq(ref xmm13, xmm10, 0x11);
                pxor(ref xmm2, xmm9);
                xorps(ref xmm2, xmm8);
                pxor(ref xmm3, xmm12);
                xorps(ref xmm3, xmm13);

                movdqu(out xmm9, rdx + 16 * 4);
                movdqu(out xmm12, rdx + 16 * 5);
                pshufb(ref xmm9, xmm11);
                pshufb(ref xmm12, xmm11);
                xmm8 = xmm4;
                xmm13 = xmm5;
                pclmulqdq(ref xmm4, xmm10, 0x00);
                pclmulqdq(ref xmm8, xmm10, 0x11);
                pclmulqdq(ref xmm5, xmm10, 0x00);
                pclmulqdq(ref xmm13, xmm10, 0x11);
                pxor(ref xmm4, xmm9);
                xorps(ref xmm4, xmm8);
                pxor(ref xmm5, xmm12);
                xorps(ref xmm5, xmm13);

                movdqu(out xmm9, rdx + 16 * 6);
                movdqu(out xmm12, rdx + 16 * 7);
                pshufb(ref xmm9, xmm11);
                pshufb(ref xmm12, xmm11);
                xmm8 = xmm6;
                xmm13 = xmm7;
                pclmulqdq(ref xmm6, xmm10, 0x00);
                pclmulqdq(ref xmm8, xmm10, 0x11);
                pclmulqdq(ref xmm7, xmm10, 0x00);
                pclmulqdq(ref xmm13, xmm10, 0x11);
                pxor(ref xmm6, xmm9);
                xorps(ref xmm6, xmm8);
                pxor(ref xmm7, xmm12);
                xorps(ref xmm7, xmm13);

                r8 -= 128;
            }
            // check if there is another 128B in the buffer to be able to fold
            while ((long)r8 >= 128);
            // ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

            rdx += 128;
            // at this point, the buffer pointer is pointing at the last y Bytes of the buffer
            // fold the 8 xmm registers to 1 xmm register with different constants

            movdqa(out xmm10, rk09, rk10);
            xmm8 = xmm0;
            pclmulqdq(ref xmm0, xmm10, 0x11);
            pclmulqdq(ref xmm8, xmm10, 0x00);
            pxor(ref xmm7, xmm8);
            xorps(ref xmm7, xmm0);

            movdqa(out xmm10, rk11, rk12);
            xmm8 = xmm1;
            pclmulqdq(ref xmm1, xmm10, 0x11);
            pclmulqdq(ref xmm8, xmm10, 0x00);
            pxor(ref xmm7, xmm8);
            xorps(ref xmm7, xmm1);

            movdqa(out xmm10, rk13, rk14);
            xmm8 = xmm2;
            pclmulqdq(ref xmm2, xmm10, 0x11);
            pclmulqdq(ref xmm8, xmm10, 0x00);
            pxor(ref xmm7, xmm8);
            pxor(ref xmm7, xmm2);

            movdqa(out xmm10, rk15, rk16);
            xmm8 = xmm3;
            pclmulqdq(ref xmm3, xmm10, 0x11);
            pclmulqdq(ref xmm8, xmm10, 0x00);
            pxor(ref xmm7, xmm8);
            xorps(ref xmm7, xmm3);

            movdqa(out xmm10, rk17, rk18);
            xmm8 = xmm4;
            pclmulqdq(ref xmm4, xmm10, 0x11);
            pclmulqdq(ref xmm8, xmm10, 0x00);
            pxor(ref xmm7, xmm8);
            pxor(ref xmm7, xmm4);

            movdqa(out xmm10, rk19, rk20);
            xmm8 = xmm5;
            pclmulqdq(ref xmm5, xmm10, 0x11);
            pclmulqdq(ref xmm8, xmm10, 0x00);
            pxor(ref xmm7, xmm8);
            xorps(ref xmm7, xmm5);

            movdqa(out xmm10, rk01, rk02);
            xmm8 = xmm6;
            pclmulqdq(ref xmm6, xmm10, 0x11);
            pclmulqdq(ref xmm8, xmm10, 0x00);
            pxor(ref xmm7, xmm8);
            pxor(ref xmm7, xmm6);

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
                xmm8 = xmm7;
                pclmulqdq(ref xmm7, xmm10, 0x11);
                pclmulqdq(ref xmm8, xmm10, 0x00);
                pxor(ref xmm7, xmm8);
                movdqu(out xmm0, rdx);
                pshufb(ref xmm0, xmm11);
                pxor(ref xmm7, xmm0);
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
            xmm2 = xmm7;

            movdqu(out xmm1, rdx - 16 + r8);
            pshufb(ref xmm1, xmm11);

            // get rid of the extra data that was loaded before
            // load the shift constant
            movdqu(out xmm0, (byte*)pshufb_shf_table + 16 - r8);

            // shift xmm2 to the left by r8 bytes
            pshufb(ref xmm2, xmm0);

            // shift xmm7 to the right by 16-r8 bytes
            pxor(ref xmm0, mask1.AsByte());
            pshufb(ref xmm7, xmm0);
            xmm1 = Sse41.BlendVariable(xmm1, xmm2, xmm0);

            // fold 16 Bytes
            xmm2 = xmm1;
            xmm8 = xmm7;
            pclmulqdq(ref xmm7, xmm10, 0x11);
            pclmulqdq(ref xmm8, xmm10, 0x00);
            pxor(ref xmm7, xmm8);
            pxor(ref xmm7, xmm2);

        _128_done:
            // compute crc of a 128-bit value
            movdqa(out xmm10, rk05, rk06); // rk05 and rk06 in xmm10
            xmm0 = xmm7;

            // 64b fold
            pclmulqdq(ref xmm7, xmm10, 0x01);
            pslldq(ref xmm0, 8);
            pxor(ref xmm7, xmm0);

            // 32b fold
            xmm0 = xmm7;
            xmm0 = Sse2.And(xmm0, mask2.AsByte());

            psrldq(ref xmm7, 12);
            pclmulqdq(ref xmm7, xmm10, 0x10);
            pxor(ref xmm7, xmm0);

        // barrett reduction
        _barrett:
            movdqa(out xmm10, rk07, rk08); // rk07 and rk08 in xmm10
            xmm0 = xmm7;
            pclmulqdq(ref xmm7, xmm10, 0x01);
            pslldq(ref xmm7, 4);
            pclmulqdq(ref xmm7, xmm10, 0x11);
            pslldq(ref xmm7, 4);
            pxor(ref xmm7, xmm0);
            uint eax = Sse41.Extract(xmm7.AsUInt32(), 1);

        _cleanup:
            return eax;

        //align 16
        _less_than_256:

            // check if there is enough buffer to be able to fold 16B at a time
            if ((long)r8 < 32)
            {
                goto _less_than_32;
            }
            xmm11 = smask.AsByte();

            // if there is, load the constants
            movdqa(out xmm10, rk01, rk02); // rk01 and rk02 in xmm10

            movd(out xmm0, ecx); // get the initial crc value
            pslldq(ref xmm0, 12); // align it to its correct place
            movdqu(out xmm7, rdx); // load the plaintext
            pshufb(ref xmm7, xmm11);
            pxor(ref xmm7, xmm0);

            // update the buffer pointer
            rdx += 16;

            // update the counter. subtract 32 instead of 16 to save one instruction from the loop
            r8 -= 32;
            goto _16B_reduction_loop;

        // align 16
        _less_than_32:
            // mov initial crc to the return value. this is necessary for zero-length buffers.
            eax = ecx;
            if (r8 == 0)
            {
                goto _cleanup;
            }

            xmm11 = smask.AsByte();

            movd(out xmm0, ecx); // get the initial crc value
            pslldq(ref xmm0, 12); // align it to its correct place

            if (r8 == 16)
            {
                goto _exact_16_left;
            }
            if ((long)r8 < 16)
            {
                goto _less_than_16_left;
            }

            movdqu(out xmm7, rdx); // load the plaintext
            pshufb(ref xmm7, xmm11);
            pxor(ref xmm7, xmm0); // xor the initial crc value
            rdx += 16;
            r8 -= 16;
            movdqa(out xmm10, rk01, rk02); // rk01 and rk02 in xmm10
            goto _get_last_two_xmms;

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
            if ((long)r8 < 4)
            {
                goto _less_than_4_left;
            }

            // load 4 Bytes
            *(uint*)r11 = *(uint*)rdx;
            r11 += 4;
            r8 -= 4;
            rdx += 4;

        _less_than_4_left:
            if ((long)r8 < 2)
            {
                goto _less_than_2_left;
            }

            // load 2 Bytes
            *(ushort*)r11 = *(ushort*)rdx;
            r11 += 2;
            r8 -= 2;
            rdx += 2;

        _less_than_2_left:
            if ((long)r8 < 1)
            {
                goto _zero_left;
            }

            // load 1 Byte
            r11[0] = rdx[0];

        _zero_left:
            movdqa(out xmm7, (byte*)&rsp);
            pshufb(ref xmm7, xmm11);
            pxor(ref xmm7, xmm0); // xor the initial crc value

            movdqu(out xmm0, (byte*)pshufb_shf_table + 16 - r9);
            pxor(ref xmm0, mask1.AsByte());

            pshufb(ref xmm7, xmm0);
            goto _128_done;

        //align 16
        _exact_16_left:
            movdqu(out xmm7, rdx);
            pshufb(ref xmm7, xmm11);
            pxor(ref xmm7, xmm0); // xor the initial crc value

            goto _128_done;

        _only_less_than_4:
            if ((long)r8 < 3)
            {
                goto _only_less_than_3;
            }

            // load 3 Bytes
            r11[0] = rdx[0];
            r11[1] = rdx[1];
            r11[2] = rdx[2];

            movdqa(out xmm7, (byte*)&rsp);
            pshufb(ref xmm7, xmm11);
            pxor(ref xmm7, xmm0); // xor the initial crc value

            psrldq(ref xmm7, 5);

            goto _barrett;

        _only_less_than_3:
            if ((long)r8 < 2)
            {
                goto _only_less_than_2;
            }

            // load 2 Bytes
            r11[0] = rdx[0];
            r11[1] = rdx[1];

            movdqa(out xmm7, (byte*)&rsp);
            pshufb(ref xmm7, xmm11);
            pxor(ref xmm7, xmm0); // xor the initial crc value

            psrldq(ref xmm7, 6);

            goto _barrett;

        _only_less_than_2:

            // load 1 Byte
            r11[0] = rdx[0];

            movdqa(out xmm7, (byte*)&rsp);
            pshufb(ref xmm7, xmm11);
            pxor(ref xmm7, xmm0); // xor the initial crc value

            psrldq(ref xmm7, 7);

            goto _barrett;
        }
    }
}
