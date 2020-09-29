using System;
using System.Numerics;

namespace SpoCManaged
{
	public static class SpoC128
	{
		//rate_bytes256: positions of rate bytes in state
		static internal byte[] rate_bytes256 = { 0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23 };
		//masking_bytes256: positions of masked capacity bytes in state
		static internal byte[] masking_bytes256 = { 8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31 };
		
		static internal byte[] InitState(byte[] Nonce, byte[] Key)
		{
			if (Nonce == null || Nonce.Length != 16)
				throw new ArgumentNullException("Nonce", "Nonce must be a 16-byte array (not null).");
			if (Key == null || Key.Length != 16)
				throw new ArgumentNullException("Key", "Nonce must be a 16-byte array (not null).");
			byte[] state = new byte[32];
			// the Nonce and the Key are split amongst the RATE and CAPACITY
			Buffer.BlockCopy(Nonce, 0, state, 0, 8);
			Buffer.BlockCopy(Nonce, 8, state, 16, 8);
			Buffer.BlockCopy(Key, 0, state, 8, 8);
			Buffer.BlockCopy(Key, 8, state, 24, 8);
			return state;
		}

		static internal void ProcessAD(ref byte[] state, ReadOnlySpan<byte> ad)
		{
			if (ad.Length == 0) return; // nothing to do, just leave
			byte i, lblen;
			int j, offset, ad128len = ad.Length / 16;
			lblen = (byte)(ad.Length % 16);

			//Absorbing associated data
			for (j = 0; j < ad128len; j++)
			{
				offset = j * 16;
				SpoCCore.sliscp_permutation256r18(ref state);
				for (i = 0; i < 8; i++)
				{
					state[i + 8] ^= ad[offset + i]; //mask
					state[i + 24] ^= ad[offset + i + 8]; //mask
				}//ctrl_ad_full
				state[0] ^= 0x20;
			}

			//Process the padded 64-bit block.
			if (lblen != 0)
			{
				offset = 16 * ad128len;
				SpoCCore.sliscp_permutation256r18(ref state);
				for (i = 0; i < lblen; i++)
					state[masking_bytes256[i]] ^= ad[offset + i]; //mask
				state[masking_bytes256[lblen]] ^= (0x80); //mask
				//ctrl_ad_par
				state[0] ^= 0x30;
			}
		}

		static internal void ProcessMessage(ref byte[] state, ReadOnlySpan<byte> m, Span<byte> ct)
		{
			if (m.Length == 0) return; // nothing to do, just leave
			byte i, lblen;
			int j, offset, m128len = m.Length / 16;
			lblen = (byte)(m.Length % 16);
			for (j = 0; j < m128len; j++)
			{
				offset = j * 16;
				SpoCCore.sliscp_permutation256r18(ref state);
				for (i = 0; i < 8; i++)
				{
					ct[offset + i] = (byte)(m[offset + i] ^ state[i]); //rate
					state[i + 8] ^= m[offset + i]; //mask
					ct[offset + i + 8] = (byte)(m[offset + i + 8] ^ state[i + 16]); // rate
					state[i + 24] ^= m[offset + i + 8]; //mask
				}
				//ctrl_pt
				state[0] ^= 0x40;
			}

			if (lblen != 0)
			{
				offset = 16 * m128len;
				SpoCCore.sliscp_permutation256r18(ref state);
				for (i = 0; i < lblen; i++)
				{
					ct[offset + i] = (byte)(m[offset + i] ^ state[rate_bytes256[i]]);
					state[masking_bytes256[i]] ^= m[offset + i];
				}
				state[masking_bytes256[lblen]] ^= 0x80; //Padding: 10*
				//ctrl_pt_par
				state[0] ^= 0x50;
			}
		}

		static internal void ProcessCiphertext(ref byte[] state, ReadOnlySpan<byte> ct, Span<byte> m)
		{
			if (m.Length == 0) return; // nothing to do, just leave
			byte i, lblen;
			int j, offset, ct128len = ct.Length / 16;
			lblen = (byte)(ct.Length % 16);

			for (j = 0; j < ct128len; j++)
			{
				offset = j * 16;
				SpoCCore.sliscp_permutation256r18(ref state);
				for (i = 0; i < 8; i++)
				{
					m[offset + i] = (byte)(ct[offset + i] ^ state[i]); //rate
					state[i + 8] ^= m[offset + i]; // mask
					m[offset + i + 8] = (byte)(ct[offset + i + 8] ^ state[i + 16]); //rate
					state[i + 24] ^= m[offset + i + 8]; // mask
				}
				//ctrl_pt
				state[0] ^= 0x40;
			}

			if (lblen != 0)
			{
				offset = 16 * ct128len;
				SpoCCore.sliscp_permutation256r18(ref state);
				for (i = 0; i < lblen; i++)
				{
					m[offset + i] = (byte)(ct[offset + i] ^ state[rate_bytes256[i]]);
					state[masking_bytes256[i]] ^= m[offset + i];
				}
				state[masking_bytes256[lblen]] ^= 0x80; //Padding: 10*
														//ctrl_pt_par
				state[0] ^= 0x50;
			}
		}

		static internal byte[] GenerateTag(ref byte[] state)
		{
			byte i;
			byte[] result = new byte[16];
			//ctrl_tag
			state[0] ^= 0x80;

			SpoCCore.sliscp_permutation256r18(ref state);
			//Extracting 128-bit tag from X1 and X3
			for (i = 0; i < 8; i++)
			{
				result[i] = state[8 + i];
				result[8 + i] = state[24 + i];
			}
			return result;
		}

		static public byte[] AEADEncrypt(byte[] Nonce, byte[] Key, ReadOnlySpan<byte> AssociatedData, ReadOnlySpan<byte> Message)
		{
			byte[] state = InitState(Nonce, Key);
			byte[] ct = new byte[Message.Length + 16];
			ProcessAD(ref state, AssociatedData);
			ProcessMessage(ref state, Message, new Span<byte>(ct));
			
			//Appending tag to the end of ciphertext
			byte[] tag = GenerateTag(ref state);
			Buffer.BlockCopy(tag, 0, ct, ct.Length - 16, 16);
			return ct;
		}

		public static byte[] AEADDecryptVerify(byte[] Nonce, byte[] Key, ReadOnlySpan<byte> AssociatedData, ReadOnlySpan<byte> Ciphertext)
		{
			if (Ciphertext.IsEmpty || Ciphertext.Length < 16)
				throw new ArgumentOutOfRangeException("Ciphertext", 
					"Not enough data. Ciphertext is expected to at least be the Tag (length >= 16 bytes).");
			byte[] state = InitState(Nonce, Key);
			byte[] pt = new byte[Ciphertext.Length - 16];
			ProcessAD(ref state, AssociatedData);
			ProcessCiphertext(ref state, Ciphertext.Slice(0, Ciphertext.Length - 16), new Span<byte>(pt));

			//Compare Tag from end of Ciphertext
			byte[] tag = GenerateTag(ref state);
			ReadOnlySpan<byte> tagCheck = Ciphertext.Slice(Ciphertext.Length - 16, 16);
			int result = 0;
			for(int i = 0; i < 16; i++) // constant time
				result |= (tag[i] ^ tagCheck[i]); // capture any and every bit that doesn't match
			if (result == 0)
				return pt; // verified
			else
			{
				//System.Diagnostics.Debug.Print("Failed Verify, resulting pt:" + BitConverter.ToString(pt).Replace("-", ""));
				return null; // FAIL!		
			}
		}
	}
}