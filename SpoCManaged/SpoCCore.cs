using System;
using System.Numerics;

namespace SpoCManaged
{
#if DEBUG
	static public class SpoCCore
#else
	static internal class SpoCCore
#endif
	{

		static public int STATEBYTES = 32; // 256 bits/8 = 32 bytes
		static public int SIMECKBYTES = 8; // 64 bits/8 = 8 bytes
		static public int SIMECKROUND = 8;
		static public int NUMSTEPSFULL = 18;
		/*
         *SC1_256: step constants, applied on S_0
         *SC2_256: step constants, applied on S_2
        */
		static public byte[] SC1_256 = { 0x8, 0x86, 0xe2, 0x89, 0xe6, 0xca, 0x17, 0x8e, 0x64, 0x6b, 0x6f, 0x2c, 0xdd, 0x99, 0xea, 0x0f, 0x04, 0x43 };// Step constants (SC_{2i})
		static public byte[] SC2_256 = { 0x64, 0x6b, 0x6f, 0x2c, 0xdd, 0x99, 0xea, 0xf, 0x4, 0x43, 0xf1, 0x44, 0x73, 0xe5, 0x0b, 0x47, 0xb2, 0xb5 };// Step constants (SC_{2i+1})
		/*
           *RC1_256: round constants of simeck box applied on S_1
           *RC2_256: round constants of simeck box applied on S_3
        */
		static public byte[] RC1_256 = { 0xf, 0x4, 0x43, 0xf1, 0x44, 0x73, 0xe5, 0xb, 0x47, 0xb2, 0xb5, 0x37, 0x96, 0xee, 0x4c, 0xf5, 0x7, 0x82 };// Round constants (RC_{2i})
		static public byte[] RC2_256 = { 0x47, 0xb2, 0xb5, 0x37, 0x96, 0xee, 0x4c, 0xf5, 0x7, 0x82, 0xa1, 0x78, 0xa2, 0xb9, 0xf2, 0x85, 0x23, 0xd9 };// Round constants (RC_{2i+1})

		static public void simeck64_box(ref byte[] data, byte rc)
		{
			UInt32 rcm, shift_1, shift_5;
			// BIG ENDIAN
			UInt32 pt_A = (UInt32)(data[0] << 24) + (UInt32)(data[1] << 16) + (UInt32)(data[2] << 8) + data[3];
			UInt32 pt_B = (UInt32)(data[4] << 24) + (UInt32)(data[5] << 16) + (UInt32)(data[6] << 8) + data[7];

			for (byte i = 0; i < SIMECKROUND; i++)
			{
				rcm = (UInt32)(0xFFFFFFFE | (rc >> i)); // round constant bit in LSB 
				// rotate 4 bytes 1 bit left as a unit
				shift_1 = BitOperations.RotateLeft(pt_A, 1);
				// rotate 4 bytes 5 bits left as a unit (already did 1, do 4 more)
				shift_5 = BitOperations.RotateLeft(shift_1, 4);
				// ts1 ^= (ts5 & tmp_pt_low) ^ tmp_pt_high ^ round const bit mask
				shift_1 ^= (UInt32)(shift_5 & pt_A) ^ pt_B ^ rcm;

				pt_B = pt_A;
				pt_A = shift_1;
			}
			// BIG ENDIAN
			data[0] = (byte)(pt_A >> 24);
			data[1] = (byte)(pt_A >> 16);
			data[2] = (byte)(pt_A >> 8);
			data[3] = (byte)(pt_A);
			data[4] = (byte)(pt_B >> 24);
			data[5] = (byte)(pt_B >> 16);
			data[6] = (byte)(pt_B >> 8);
			data[7] = (byte)(pt_B);
		}

		static public void sliscp_permutation256r18(ref byte[] input)
		{
			byte i, j;
			byte[] tmp_pt = new byte[STATEBYTES];
			byte[] tmp_block = new byte[SIMECKBYTES];
			byte[] simeck_inp = new byte[SIMECKBYTES];

			Buffer.BlockCopy(input, 0, tmp_pt, 0, STATEBYTES);

			for (i = 0; i < NUMSTEPSFULL; i++)
			{
				Buffer.BlockCopy(tmp_pt, 0, tmp_block, 0, SIMECKBYTES);
				Buffer.BlockCopy(tmp_pt, SIMECKBYTES, simeck_inp, 0, SIMECKBYTES);
								
				simeck64_box(ref simeck_inp, RC1_256[i]);

				for (j = 0; j < SIMECKBYTES; j++)
					tmp_block[j] ^= simeck_inp[j]; //x0^F(x1)

				// Add round constant: RC[0]^x0^F(x1)
				for (j = 0; j < SIMECKBYTES - 1; j++)
					tmp_block[j] ^= 0xff;
				tmp_block[SIMECKBYTES - 1] ^= SC1_256[i]; 

				Buffer.BlockCopy(simeck_inp, 0, tmp_pt, 0, SIMECKBYTES);
				Buffer.BlockCopy(tmp_pt, 3 * SIMECKBYTES, simeck_inp, 0, SIMECKBYTES);

				simeck64_box(ref simeck_inp, RC2_256[i]);

				for (j = 0; j < SIMECKBYTES; j++)
					tmp_pt[SIMECKBYTES + j] = (byte)(tmp_pt[2 * SIMECKBYTES + j] ^ simeck_inp[j]); //x2^F(x3)

				// Add round constant: RC[1]^x2^F(x3)
				for (j = 0; j < SIMECKBYTES - 1; j++)
					tmp_pt[SIMECKBYTES + j] ^= 0xff;
				tmp_pt[2 * SIMECKBYTES - 1] ^= SC2_256[i]; // x1' = RC[1]^x2^F(x3)//

				Buffer.BlockCopy(simeck_inp, 0, tmp_pt, 2 * SIMECKBYTES, SIMECKBYTES);
				Buffer.BlockCopy(tmp_block, 0, tmp_pt, 3 * SIMECKBYTES, SIMECKBYTES);
			}
			Buffer.BlockCopy(tmp_pt, 0, input, 0, STATEBYTES);
		}
	}
}
