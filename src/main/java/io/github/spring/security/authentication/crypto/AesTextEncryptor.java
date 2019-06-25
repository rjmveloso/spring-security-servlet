package io.github.spring.security.authentication.crypto;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.crypto.encrypt.TextEncryptor;

public class AesTextEncryptor implements TextEncryptor {

	private Cipher encrypt;
	private Cipher decrypt;

	public AesTextEncryptor(String key) {
		byte[] data = getSha512Digest().digest(key.getBytes());
		final SecretKey skey = new SecretKeySpec(data, "AES");
		encrypt = getAesCipher(Cipher.ENCRYPT_MODE, skey);
		decrypt = getAesCipher(Cipher.DECRYPT_MODE, skey);
	}

	@Override
	public String encrypt(String text) {
		return new String(process(encrypt, text.getBytes()));
	}

	@Override
	public String decrypt(String text) {
		return new String(process(decrypt, text.getBytes()));
	}

	private static byte[] process(Cipher cipher, byte[] data) {
		try {
			return cipher.doFinal(data);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	private static Cipher getAesCipher(int opmode, Key key) {
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(opmode, key);
			return cipher;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	private static MessageDigest getSha512Digest() {
		try {
			return MessageDigest.getInstance("SHA-512");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage());
		}
	}
}
