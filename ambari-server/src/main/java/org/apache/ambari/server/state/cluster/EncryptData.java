package org.apache.ambari.server.state.cluster;
import java.security.Key;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;


public class EncryptData {
	private static final String algorithm = "PBEWITHMD5andDES";
	private static final int iterationCount = 100;
	private static final byte[] salt = "frontsur".getBytes();
	
	private static Key toKey(String password) throws Exception{
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
		SecretKey secretKey = keyFactory.generateSecret(keySpec);
		
		return secretKey;
	}
	
	public static byte[] encrypt(byte[] data,String password) 
		throws Exception {
		Key key = toKey(password);
		
		PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, iterationCount);
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
		
		return cipher.doFinal(data);
	}
	
	public static byte[] decrypt(byte[] data,String password)
		throws Exception{
		Key key = toKey(password);
		
		PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, iterationCount);
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
		
		return cipher.doFinal(data);
	}
	//for testing
	public static void main(String[] args) throws Exception {
		String origindata = "cjwhust";
		String password = "dx";
		
		String encryptString = new String(EncryptData.encrypt(origindata.getBytes(), password), "ISO-8859-1");
		System.out.println("encryptString is : "+encryptString);
		
		String decryptString = new String(EncryptData.decrypt(encryptString.getBytes("ISO-8859-1"), password));
		System.out.println("decryptString is : "+decryptString);
		
	}
}
