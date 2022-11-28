/*
Name: Sally
UOW ID: 4603229

Source code reference:
UDP: https://www.geeksforgeeks.org/working-udp-datagramsockets-java/
RSA: https://gist.github.com/nielsutrecht/855f3bef0cf559d8d23e94e2aecd4ede
RC4: https://github.com/oxee/RC4/blob/master/RC4.java
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
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Arrays;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;


public class Client 
{
  // For font color purpose
	public static final String ANSI_PURPLE = "\u001B[35m";
	public static final String ANSI_BLUE = "\u001B[34m";
  public static final String ANSI_RESET = "\u001B[0m";
  
  // Start of main function
  public static void main(String[] args) throws SocketException, IOException,Exception 
  {
    // 128-bit Nonce
		byte[] nonce = new byte[16];
		new SecureRandom().nextBytes(nonce);
		String NB = convertBytesToHex(nonce) ;
		System.out.println("NB: " + NB); 

    // Prompt user to enter username and password
		System.out.println("Enter the username: ") ;
		BufferedReader clientRead =new BufferedReader(new InputStreamReader(System.in));
		String username = clientRead.readLine();

		System.out.println("Enter the password: ");
		String password = clientRead.readLine();

    // Start UDP
		InetAddress IP = InetAddress.getByName("127.0.0.1");
		DatagramSocket clientSocket = new DatagramSocket();
		DatagramPacket sendPacket = new DatagramPacket(nonce, nonce.length, IP, 9876);
		clientSocket.send(sendPacket);

    // Receive public key from Alice
		byte[] receive_pub_key = new byte[162];
		DatagramPacket receivePacket = new DatagramPacket(receive_pub_key, receive_pub_key.length);
		clientSocket.receive(receivePacket);
		String public_key = Base64.getEncoder().encodeToString( receivePacket.getData());
		System.out.print("\nReceived_public_key: " + public_key);

    // Receive Nonce from Alice
		byte[] receive_nonce = new byte[16];
		DatagramPacket receivePacket2= new DatagramPacket(receive_nonce, receive_nonce.length);
		clientSocket.receive(receivePacket2);
		String NA = new String(convertBytesToHex(receivePacket2.getData()));
		System.out.print("\n\nReceived_nonce from Alice: " + NA);

		String C1_message = "Hello" ;
		byte[] cipher_text = encrypt(C1_message , public_key) ;

		String c2message = username + "," + password ;
		String key = C1_message ;
		rc4 rc4_algo = new rc4(key.getBytes());
		byte[] ciphertext_2 = rc4_algo.encrypt(c2message.getBytes());
		System.out.println("\n\nRC4 encrypted text: "+Base64.getEncoder().encodeToString(ciphertext_2));

		DatagramPacket sendPacket3 = new DatagramPacket(cipher_text, cipher_text.length, IP, 9876);
		clientSocket.send(sendPacket3);

		DatagramPacket sendPacket4 = new DatagramPacket(ciphertext_2, ciphertext_2.length, IP, 9876);
		clientSocket.send(sendPacket4);

    // Receiving message from Alice
		byte[]msg = new byte[32];
		DatagramPacket receivePacket3= new DatagramPacket(msg, msg.length);
		clientSocket.receive(receivePacket3);
    String s = new String(receivePacket3.getData(), 0, receivePacket3.getLength());

    // If connection successful
		if (s.equals("Successful") )
		{
      System.out.println("Connection established with server.\n");
      
			// Compute session
			String ssk =  sha1hash(C1_message + NA + NB) ;

			while(true)
			{
				byte[] receivebuffer = new byte[1024];
				byte[] sendbuffer  = new byte[1024];

        // To receive message from Alice
				DatagramPacket server_data = new DatagramPacket(receivebuffer, receivebuffer.length);
				clientSocket.receive(server_data);

				String data_recv = new String(rc4_algo.decrypt(server_data.getData()),0,server_data.getLength());
        // For debugging
        //System.out.println(data_recv);
				String final_recv_msg =  decrypted_msg(Arrays.copyOfRange(server_data.getData(), 0,server_data.getLength()), data_recv, ssk);
				System.out.println(ANSI_PURPLE + "\n\nAlice : " + ANSI_RESET + final_recv_msg);
				if(final_recv_msg.equalsIgnoreCase("exit"))
				{
					System.out.println("Connection ended by server");
					break;
				}
				System.out.print(ANSI_BLUE + "Bob : " + ANSI_RESET);
				BufferedReader clientread = new BufferedReader(new InputStreamReader (System.in));
				String client_msg = clientread.readLine();

				sendbuffer = encrypted_msg(client_msg , ssk , rc4_algo);
				DatagramPacket client_data = new DatagramPacket(sendbuffer, sendbuffer.length, IP,9876);
				clientSocket.send(client_data); 
				// If exit
				if(client_msg.equalsIgnoreCase("exit"))
				{
					System.out.println("Connection ended by client");
					break;
				}
			}
		} // End of successful connection
		else
		{
			System.out.println("Authentication failed !!!");
			clientSocket.close();
		} // End of failed authentication
		clientSocket.close();
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
		msg_enc_64 = new String(Base64.getEncoder().encode(msg_enc)); // Encrypted message in Base64

    // Print info for Bob as sender
		System.out.println("\n++++++++++++++++++++++++++++++++  Sender  ++++++++++++++++++++++++++++++++");
		System.out.println("Message being encrpyted is: "+msg);
		System.out.println("Encrypted message (Base64): "+ msg_enc_64);
		System.out.println("Hash for "+" msg is "+ hash_m);

		return msg_enc;
	} // End of encrypted_msg

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

    // Print info for Bob as receiver
		System.out.println("\n++++++++++++++++++++++++++++++++  Receiver  ++++++++++++++++++++++++++++++++");
		System.out.println("Hash for the message from Alice is: "+h_msg);
		System.out.println("h' is : "+ hash_prime);
		System.out.println("Encrypted message from Alice (Base64): "+ ori_msg_64);
		System.out.println("Decrypted message from Alice is: "+ p_msg);

    // Only return decrypted message if h=h'
		if (h_msg.equals(hash_prime)) 
			return p_msg;
		else
			return "Packet Rejected";
	} // End of decrypted_msg

  public static byte[] encrypt(String data, String publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,IOException 
  {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
		return cipher.doFinal(data.getBytes());
  } // End of encrypt
  
  public static String sha1hash(String value) 
  {
		String sha1 = "";

		// With the java libraries
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

		return sha1 ;
	} // End of sha1hash

  public static String decrypt(String data, PrivateKey pKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException 
  {
		return decrypt(Base64.getDecoder().decode(data.getBytes()), pKey);
	} // End of decrypt

  public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException 
  {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return new String(cipher.doFinal(data));
	} // End of decrypt


  public static PublicKey getPublicKey(String base64PublicKey)
  {
		PublicKey publicKey = null;
    try
    {
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKey = keyFactory.generatePublic(keySpec);
			return publicKey;
    } 
    catch (NoSuchAlgorithmException e) 
    {
			e.printStackTrace();
    } 
    catch (InvalidKeySpecException e) 
    {
			e.printStackTrace();
		}
		return publicKey;
  } // End of PublicKey
  
} // End of Client class
