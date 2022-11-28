/*
Name: Sally
UOW ID: 4603229

Source code reference:
UDP: https://www.geeksforgeeks.org/working-udp-datagramsockets-java/
RSA: https://gist.github.com/nielsutrecht/855f3bef0cf559d8d23e94e2aecd4ede
 */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.*;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Arrays;
import java.security.spec.X509EncodedKeySpec;
import java.io.*;
import javax.crypto.*;
import java.security.InvalidKeyException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class Server 
{
  // For font color purpose
	public static final String ANSI_PURPLE = "\u001B[35m";
	public static final String ANSI_BLUE = "\u001B[34m";
	public static final String ANSI_RESET = "\u001B[0m";

  // Start of main function
  public static void main(String[] args) throws SocketException, IOException,NoSuchAlgorithmException,InvalidKeySpecException,Exception 
  {
    // 128-bit Nonce
    byte[] receivebuffer = new byte[16];
    byte[] nonce = new byte[16];
    new SecureRandom().nextBytes(nonce);
    String NA = convertBytesToHex(nonce);
    System.out.println("NA: "+ NA);

    // Start UDP socket
    DatagramSocket serverSocket = new DatagramSocket(9876);
    DatagramPacket recvdpkt = new DatagramPacket(receivebuffer, receivebuffer.length);
    serverSocket.receive(recvdpkt);
    InetAddress IP = recvdpkt.getAddress();
    int portno = recvdpkt.getPort();
    
    // Receive NB from Bob
    String NB = convertBytesToHex(recvdpkt.getData());
    System.out.println("\nNB: "+ NB);

    // Read the private key bytes
    Path path = Paths.get("k_file.key");
    // For debugging
    //System.out.println(path);
    byte[] bytes = Files.readAllBytes(path);
    // For debugging
    //System.out.println(bytes);
    Base64.Decoder b64 = Base64.getDecoder();
    String temp = new String(bytes);
    byte[] decoded = b64.decode(temp);

    // Generate private key
    PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(decoded);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    PrivateKey pvt = kf.generatePrivate(ks);
    System.out.println("\nPRIVATE KEY: "+ Base64.getEncoder().encodeToString(pvt.getEncoded()));

    // Read all the public key bytes
    Path path2 = Paths.get("k_file.pub");
    byte[] bytes2 = Files.readAllBytes(path2);
    String temp2 = new String(bytes2);
    byte[] decoded2 = b64.decode(temp2);

    // Generate public key
    X509EncodedKeySpec ks2 = new X509EncodedKeySpec(decoded2);
    KeyFactory kf2 = KeyFactory.getInstance("RSA");
    PublicKey pub = kf2.generatePublic(ks2);
    System.out.println("\nPUBLIC KEY: "+ Base64.getEncoder().encodeToString(pub.getEncoded()));

    DatagramPacket sendPacket = new DatagramPacket(pub.getEncoded(), pub.getEncoded().length, IP,portno);
    serverSocket.send(sendPacket); 

    DatagramPacket sendPacket2 = new DatagramPacket(nonce, nonce.length, IP,portno);
    serverSocket.send(sendPacket2); 

    // C1 received
    byte[] C1 = new byte[128] ;
    DatagramPacket recvdpkt2 = new DatagramPacket(C1, C1.length);
    serverSocket.receive(recvdpkt2);
    String encrypted  = Base64.getEncoder().encodeToString(C1);
    System.out.println("\nEncrypted text: " +encrypted);

    // C2 received (username+password)
    byte[] C2 = new byte[16];
    DatagramPacket recvdpkt3 = new DatagramPacket(C2, C2.length);
    serverSocket.receive(recvdpkt3);

    // Decrypting C1
    String original_text = decrypt(C1, pvt) ;
    System.out.println("\nDecrypted text C1: "+original_text);

    // Decrypting username+password
    rc4 rc4algo = new rc4(original_text.getBytes());
    String u_name_pass = new String(rc4algo.decrypt(recvdpkt3.getData()), 0 ,recvdpkt3.getLength());
    System.out.println("\nDecrypted username and password text: "+u_name_pass);

    // Matching password
    String[] portions = u_name_pass.split(",");
    String password  = portions[1];
    File file = new File("password.txt");
    BufferedReader br = new BufferedReader(new FileReader(file));

    String pass;
    pass = br.readLine();

    // Check for correct password and establish connection
    if (pass.equalsIgnoreCase(password))
    {
      String s = "Successful" ;
      System.out.println("Connection Established with Client.\n");
      byte [] s_bytes = s.getBytes();
      DatagramPacket sendPacket3 = new DatagramPacket(s_bytes, s_bytes.length, IP,portno);
      serverSocket.send(sendPacket3); 

      // Compute session key
      String ssk = sha1hash(original_text + NA + NB);

      while(true) 
      {
        byte [] receivebuffer2 = new byte[1024];
        byte[] sendbuffer  = new byte[1024];

        System.out.print(ANSI_PURPLE + "Alice : " + ANSI_RESET);
        BufferedReader serverRead = new BufferedReader(new InputStreamReader (System.in));
        String serverdata = serverRead.readLine();

        sendbuffer = encrypted_msg(serverdata , ssk , rc4algo);
        DatagramPacket server_data = new DatagramPacket(sendbuffer, sendbuffer.length, IP,portno);
        serverSocket.send(server_data); 

        if(serverdata.equalsIgnoreCase("exit"))
        {
          System.out.println("Connection ended by Server.");
          break;
        }

        // Receive message
        DatagramPacket client_data = new DatagramPacket(receivebuffer2, receivebuffer2.length);
        serverSocket.receive(client_data);

        String data_recv = new String(rc4algo.decrypt(client_data.getData()), 0 , client_data.getLength());
        String final_recv_msg =  decrypted_msg(Arrays.copyOfRange(client_data.getData(), 0,client_data.getLength()) , data_recv, ssk);
        System.out.println(ANSI_BLUE + "\n\nBob : " + ANSI_RESET + final_recv_msg);
        if(final_recv_msg.equalsIgnoreCase("exit"))
        {
          System.out.println("Connection ended by Client");
          break;
        }
      }
    }
    else // Authentication fail
    {
      DatagramPacket sendPacket3 = new DatagramPacket("Authentication Failed".getBytes(), "Authentication Failed".length(), IP,portno);
      serverSocket.send(sendPacket3); 
      serverSocket.close();
    }
    serverSocket.close();
  } // End of main function


  private static String convertBytesToHex(byte[] bytes) 
  {
		StringBuilder result = new StringBuilder();
    for (byte temp : bytes) 
    {
			result.append(String.format("%02x", temp));
		}
		return result.toString();
	} // End of convertBytesToHex

  public static String decrypt(String data, PrivateKey pKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,IOException 
  {
		return decrypt(Base64.getDecoder().decode(data.getBytes()), pKey);
	} // End of decrypt

  public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,IOException 
  {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return new String(cipher.doFinal(data));
  } // End of decrypt
  
  public static String sha1hash(String value) 
  {
		String sha1 = "";

		// With the Java libraries
    try 
    {
			MessageDigest digest = MessageDigest.getInstance("SHA-1");
			digest.reset();
			digest.update(value.getBytes("utf8"));
			sha1 = String.format("%040x", new BigInteger(1, digest.digest()));
    } 
    catch (Exception e)
    {
			e.printStackTrace();
		}

		return sha1;
	} // End of sha1hash

  private static byte[] encrypted_msg (String msg, String ssk, rc4 rc_4) 
  {
		String hash_m = "";
		String delim = ",";
		String msg_enc_t;
		byte[] msg_enc;
		String msg_enc_64; // To store encrypted message in Base64

    // Computing message's h
		hash_m = ssk + msg + ssk;
    hash_m = sha1hash(hash_m);
    
		msg_enc_t = msg + delim + hash_m;
		msg_enc = rc_4.encrypt(msg_enc_t.getBytes());
		msg_enc_64 = new String(Base64.getEncoder().encode(msg_enc));

    // Print info for Alice as sender
		System.out.println("\n++++++++++++++++++++++++++++++++  Sender  ++++++++++++++++++++++++++++++++");
		System.out.println("Message being encrpyted is: "+msg);
		System.out.println("Encrypted message (Base64): "+ msg_enc_64);
		System.out.println("Hash for "+" msg is "+ hash_m);

		return msg_enc;
	}// End of encrypted_msg

  private static String decrypted_msg(byte[] ori_msg, String msg, String ssk) 
  {
		String msg_encrypted = msg;
		String h_msg = "";
		String p_msg = "";
		String hash_prime = "";
		String ori_msg_64; // To store decrypted message in Base64

		String[] portions = msg_encrypted.split(",");
		p_msg = portions[0];
		h_msg = portions[1];
		ori_msg_64 = new String(Base64.getEncoder().encode(ori_msg)); // decrypted message in Base64

    // Computing message's h'
		hash_prime = ssk + p_msg + ssk;
		hash_prime = sha1hash(hash_prime);

    // Print info for Alice as receiver
		System.out.println("\n++++++++++++++++++++++++++++++++  Receiver  ++++++++++++++++++++++++++++++++");
		System.out.println("Hash for the message from Bob is: "+h_msg);
		System.out.println("h' is : "+ hash_prime);
		System.out.println("Encrypted message from Bob (Base64): "+ ori_msg_64);
		System.out.println("Decrypted message from Bob is: "+ p_msg);

    // Only return decrypted message if h=h'
		if (h_msg.equals(hash_prime)) 
			return p_msg;
		else
			return "Packet Rejected";
	} // End of decrypted_msg

} // End of Server class

