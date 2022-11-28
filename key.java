/*
Name: Sally
UOW ID: 4603229

Source code reference:
RSA: https://gist.github.com/nielsutrecht/855f3bef0cf559d8d23e94e2aecd4ede
 */

import java.io.Writer;
import java.io.FileWriter;
import java.io.OutputStreamWriter;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

public class key
{
	static private Base64.Encoder encoder = Base64.getEncoder();

	static private void writeBase64(Writer out,Key key)
			throws java.io.IOException
	{
		byte[] buf = key.getEncoded();
		out.write(encoder.encodeToString(buf));
	}

	static public void main(String[] args) throws Exception
	{
		String outFile = "k_file" ;

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");

		// Initialize with keySize: typically 2048 for RSA
		kpg.initialize(1024);
		KeyPair kp = kpg.generateKeyPair();

		Writer out = null;
		try {
			out = new FileWriter(outFile + ".key");

			System.err.println("Private key format: " + kp.getPrivate().getFormat());

			//out.write("-----BEGIN RSA PRIVATE KEY-----\n");
			writeBase64(out, kp.getPrivate());
			//out.write("-----END RSA PRIVATE KEY-----\n");

			if (outFile != null) 
			{
				out.close();
				out = new FileWriter(outFile + ".pub");
			}

			System.err.println("Public key format: " + kp.getPublic().getFormat());

			//out.write("-----BEGIN RSA PUBLIC KEY-----\n");
			writeBase64(out, kp.getPublic());
			//out.write("-----END RSA PUBLIC KEY-----\n");

		} finally {
			if (out != null) 
				out.close();
		}
	} // End of main function

} // End of key class
