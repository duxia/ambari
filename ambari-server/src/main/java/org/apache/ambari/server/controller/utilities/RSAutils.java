package org.apache.ambari.server.controller.utilities;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;


public class RSAutils {
	private static final String KEY_ALGORITHM = "RSA";
	private static final int MAX_ENCRYPT_BLOCK = 117;
	private static final int MAX_DECRYPT_BLOCK = 128;
	
	public static void genKeyPairFile(String privateKeyFile,String publicKeyFile) throws GeneralSecurityException{
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGen.initialize(1024);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
		//write down to file
		ObjectOutputStream privateKeyStream;
		ObjectOutputStream publicKeyStream;
		
		try {
			privateKeyStream = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
			privateKeyStream.writeObject(privateKey);
			privateKeyStream.flush();
			privateKeyStream.close();

			publicKeyStream = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
			publicKeyStream.writeObject(publicKey);
			publicKeyStream.flush();
			publicKeyStream.close();
			System.out.println("make file successful!");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static byte[] encrypt(Key k,byte[] data) throws GeneralSecurityException, IOException{
		Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, k);
		
		return Base64.encodeBase64(handleData(data, cipher, MAX_ENCRYPT_BLOCK));
	}

	public static String encrypt(Key k,String data) throws IOException, GeneralSecurityException {
		byte[] encryptbyte = encrypt(k, data.getBytes("UTF-8"));
		return new String(encryptbyte, "UTF-8");
	}
	
	public static byte[] decrypt(Key k,byte[] data) throws GeneralSecurityException, IOException {
		Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, k);

		return handleData(Base64.decodeBase64(data), cipher, MAX_DECRYPT_BLOCK);
	}

	public static String decrypt(Key k,String data) throws IOException, GeneralSecurityException {
		byte[] decryptbyte = decrypt(k, data.getBytes("UTF-8"));
		return new String(decryptbyte,"UTF-8");
	}
	
	private static byte[] handleData(byte[] data,Cipher cipher,int max_block) throws GeneralSecurityException, IOException {
		int dataLength=data.length;
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		int offset=0;
		int block;
		byte[] cache;
		while (dataLength-offset>0) {
			if(dataLength - offset >= max_block) {
				block = max_block;
			} else {
				block = dataLength-offset;
			}
			cache = cipher.doFinal(data, offset, block);
			byteArrayOutputStream.write(cache, 0, cache.length);
			offset+=block;
		}
		
		
		byte[] resultBytes= byteArrayOutputStream.toByteArray();
		byteArrayOutputStream.close();
		return resultBytes;
	}
	
	public static RSAPublicKey getPublicKey(String publicKeyFile) throws IOException, ClassNotFoundException {
		ObjectInputStream publicKeyInputStream = new ObjectInputStream(new FileInputStream(publicKeyFile));
		RSAPublicKey publicKey = (RSAPublicKey) publicKeyInputStream.readObject();
		publicKeyInputStream.close();
		return publicKey;
	}
	
	public static RSAPrivateKey getPrivateKey(String privateKeyFile) throws IOException, ClassNotFoundException{
		ObjectInputStream privateKeyInputStream = new ObjectInputStream(new FileInputStream(privateKeyFile));
		RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyInputStream.readObject();
		privateKeyInputStream.close();
		return privateKey;
	}
}
