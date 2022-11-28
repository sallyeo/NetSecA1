/*
Name: Sally
UOW ID: 4603229

Source code reference:
RC4: https://github.com/oxee/RC4/blob/master/RC4.java
*/

public class rc4
{
	private byte[] S = new byte[4096];
	private byte[] T = new byte[4096];

	public rc4 (byte[] key)
	{
		int keylen, j;
		byte t;

		for (int jj = 0 ; jj < 256 ; jj++)
		{	
			keylen = key.length;
			S[jj] = (byte) jj;
			T[jj] = (byte) key[jj % keylen];
		}

		j = 0;
		for (int jj = 0 ; jj < 256 ; jj++)
		{
			j = ((j + S[jj] + T[jj]) % 256) & 0xFF;

			t = S[jj];
			S[jj] = S[j];
			S[j] = t;
		}
	}// End of constructor

	public static String byteToString (byte[] data)
	{
		return data.toString();
	} // End of byteToString

	public static byte[] stringToByte(String data)
	{
		return data.getBytes();
	} // End of stringToByte

	public byte[] encrypt(byte[] plaintext)
	{	
		int	j = 0, i = 0, t, k;
		byte	temp;
		byte[]	pt,ct, s;

		// Deep copy
		s = S.clone();

		pt = plaintext;
		ct = new byte[pt.length];
		for (int jj = 0 ; jj < pt.length; jj++)
		{
			i = ((i + 1) % 256) & 0xFF;
			j = ((j + s[i]) % 256) & 0xFF;

			// Classic swap
			temp	= s[jj];
			s[jj] = s[j];
			s[j] = temp;

			t = ((s[i] + s[j]) % 256) & 0xFF;
			k = s[t];
			ct[jj] = (byte) (k ^ pt[jj]);
		}

		return ct;
	} // End of encrypt

	public byte[] decrypt(byte[] ciphertext)
	{
		return encrypt(ciphertext);
	} // End of decrypt

} // End of rc4 class
