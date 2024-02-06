
import java.util.Calendar;
import java.util.Date;
import java.text.SimpleDateFormat;

import org.apache.commons.codec.binary.Base64;
import org.json.simple.parser.JSONParser;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.io.*;
import java.sql.*;
class EVP_decrypt{
private static Date ADConversion(String input,SimpleDateFormat dateFormat) throws Exception {
		Date temp = dateFormat.parse(input);
		Calendar c = Calendar.getInstance();
		c.setTime(temp); 
		c.add(Calendar.YEAR, -543);
		Trace.info("AD. year conv. : "+c.getTime());
		return c.getTime();
	}


	private static byte[] EVP_BytesToKey(String filePath, String password) throws Exception {
		String contents = new String(Files.readAllBytes(Paths.get(filePath)));
		// System.out.println(contents);
		byte[] decodedString = Base64.decodeBase64(contents);
		byte[] magic_byte = { 83, 97, 108, 116, 101, 100, 95, 95 };
		for (int e = 0; e < magic_byte.length; e++) {
			if (decodedString[e] != magic_byte[e]) {
				System.out.println("Error: invalid magic Salted__");
				throw new Exception("Error: invalid magic Salted__");
			}
		}
		
		///////EVP_BytesToKey///////
		byte[] salt = Arrays.copyOfRange(decodedString, 8, 16);
		byte[] passphase_byte = password.getBytes();
		

		byte[] java_key_iv = bytes_to_key(passphase_byte, salt, 32 + 16);
		byte[] java_key = Arrays.copyOfRange(java_key_iv, 0, 32);
		byte[] java_iv = Arrays.copyOfRange(java_key_iv, 32, java_key_iv.length);
		//printByte(java_key);
		//printByte(java_iv);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec sks = new SecretKeySpec(java_key, "AES");
		cipher.init(Cipher.DECRYPT_MODE, sks, new IvParameterSpec(java_iv));
		byte[] result = cipher.doFinal(Arrays.copyOfRange(decodedString, 16, decodedString.length ));
		
		String s = new String(result, StandardCharsets.UTF_8);
		String raw_decrypt_string = s.substring(s.indexOf("\"data\":[")+8, s.indexOf("]}"));
		String[] split_decrypt_string = raw_decrypt_string.split(",");
		byte[] decrypt_byte = new byte[split_decrypt_string.length];
		
		for(int e = 0;e<split_decrypt_string.length;e++) {
			decrypt_byte[e] = (byte)Integer.parseInt(split_decrypt_string[e]);
		}
		return decrypt_byte;
	}

	private static byte[] bytes_to_key(byte[] passphase, byte[] salt, int iv_len) {

		
		try {
			passphase = concat(passphase, salt);
			
			byte[] final_key = MessageDigest.getInstance("MD5").digest(passphase);
			byte[] key = final_key;
			while (final_key.length < iv_len) {
				key = MessageDigest.getInstance("MD5").digest(concat(key, passphase));
				final_key = concat(final_key, key);
				
			}
			//print_byte(final_key);
			
			return Arrays.copyOfRange(final_key, 0, iv_len);	
			
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	private static void writeByteToFile(byte[] barr,String save_path) {
		try (FileOutputStream fos = new FileOutputStream(save_path)) {
		      fos.write(barr);
		      //fos.close // no need, try-with-resources auto close
		}catch(Exception e) {}
	}
	private static void printByte(byte[] array) {
		for(int e=0;e<array.length;e++) {
			System.out.print((array[e] & 0xff)+",");
		}System.out.println();
	}
	public static byte[] concat(byte[] first, byte[] second) {
		byte[] result = Arrays.copyOf(first, first.length + second.length);
		System.arraycopy(second, 0, result, first.length, second.length);
		return result;
	}
    
}
  
