// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using Aes = System.Runtime.Intrinsics.Arm.Aes;

namespace SharpHashing.Crc
{
    // Helpers which provide equivalent intrinsics for Intel and ARM architectures. Should only be used
    // if the intrinsics are available.
    internal static class VectorHelper
    {
        // Pclmulqdq implies support for SSE2
        public static bool IsSupported => (Ssse3.IsSupported && Pclmulqdq.IsSupported) || (Aes.IsSupported && AdvSimd.IsSupported);

        // Performs carryless multiplication of the upper pairs of source and constants and the lower pairs of source and constants,
        // then folds them into target using carryless addition.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<ulong> FoldPolynomialPair(Vector128<ulong> target, Vector128<ulong> source, Vector128<ulong> constants)
        {
            target ^= CarrylessMultiplyUpper(source, constants);
            target ^= CarrylessMultiplyLower(source, constants);

            return target;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<ulong> CarrylessMultiplyLower(Vector128<ulong> left, Vector128<ulong> right)
        {
            if (Pclmulqdq.IsSupported)
            {
                return Pclmulqdq.CarrylessMultiply(left, right, 0x00);
            }

            if (Aes.IsSupported)
            {
                return Aes.PolynomialMultiplyWideningLower(left.GetLower(), right.GetLower());
            }

            ThrowUnreachableException();
            return default;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<ulong> CarrylessMultiplyUpper(Vector128<ulong> left, Vector128<ulong> right)
        {
            if (Pclmulqdq.IsSupported)
            {
                return Pclmulqdq.CarrylessMultiply(left, right, 0x11);
            }

            if (Aes.IsSupported)
            {
                return Aes.PolynomialMultiplyWideningUpper(left, right);
            }

            ThrowUnreachableException();
            return default;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<ulong> CarrylessMultiplyLeftUpperRightLower(Vector128<ulong> left, Vector128<ulong> right)
        {
            if (Pclmulqdq.IsSupported)
            {
                return Pclmulqdq.CarrylessMultiply(left, right, 0x01);
            }

            if (Aes.IsSupported)
            {
                return Aes.PolynomialMultiplyWideningLower(left.GetUpper(), right.GetLower());
            }

            ThrowUnreachableException();
            return default;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<ulong> CarrylessMultiplyLeftLowerRightUpper(Vector128<ulong> left, Vector128<ulong> right)
        {
            if (Pclmulqdq.IsSupported)
            {
                return Pclmulqdq.CarrylessMultiply(left, right, 0x10);
            }

            if (Aes.IsSupported)
            {
                return Aes.PolynomialMultiplyWideningLower(left.GetLower(), right.GetUpper());
            }

            ThrowUnreachableException();
            return default;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<ulong> ShiftRightInVector(
            Vector128<ulong> operand,
            [ConstantExpected(Max = (byte)15)] byte numBytesToShift)
        {
            if (Sse2.IsSupported)
            {
                return Sse2.ShiftRightLogical128BitLane(operand, numBytesToShift);
            }

            if (AdvSimd.IsSupported)
            {
                return AdvSimd.ExtractVector128(operand.AsByte(), Vector128<byte>.Zero, numBytesToShift).AsUInt64();
            }

            ThrowUnreachableException();
            return default;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<ulong> ShiftLeftInVector(
            Vector128<ulong> operand,
            [ConstantExpected(Max = (byte)15)] byte numBytesToShift)
        {
            if (Sse2.IsSupported)
            {
                return Sse2.ShiftLeftLogical128BitLane(operand, numBytesToShift);
            }

            if (AdvSimd.IsSupported)
            {
                return AdvSimd.ExtractVector128(Vector128<byte>.Zero, operand.AsByte(), numBytesToShift).AsUInt64();
            }

            ThrowUnreachableException();
            return default;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Shuffle(Vector128<byte> vector, Vector128<byte> indices)
        {
            if (Ssse3.IsSupported)
            {
                return Ssse3.Shuffle(vector, indices);
            }

            var maskedIndices = indices & Vector128.Create((byte)0x8f);
            
            if (AdvSimd.Arm64.IsSupported)
            {
                return AdvSimd.Arm64.VectorTableLookup(vector, maskedIndices);
            }

            if (AdvSimd.IsSupported)
            {
                return Vector128.Create(
                    AdvSimd.VectorTableLookup(vector, maskedIndices.GetLower()),
                    AdvSimd.VectorTableLookup(vector, maskedIndices.GetUpper()));
            }

            ThrowUnreachableException();
            return default;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> BlendVariable(Vector128<byte> left, Vector128<byte> right, Vector128<byte> mask)
        {
            if (Sse41.IsSupported)
            {
                return Sse41.BlendVariable(left, right, mask);
            }

            if (Sse2.IsSupported)
            {
                return Sse2.Or(Sse2.And(left, mask), Sse2.AndNot(mask, right));
            }

            if (AdvSimd.IsSupported)
            {
                // Use a signed shift right to create a mask with the sign bit
                Vector128<sbyte> select = AdvSimd.ShiftRightArithmetic(mask.AsSByte(), 7);
                return AdvSimd.BitwiseSelect(select.AsByte(), right, left);
            }

            ThrowUnreachableException();
            return default;
        }

        [DoesNotReturn]
        private static void ThrowUnreachableException()
        {
            throw new UnreachableException();
        }
    }
}
