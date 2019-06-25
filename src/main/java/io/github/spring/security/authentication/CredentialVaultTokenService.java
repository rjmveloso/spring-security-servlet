package io.github.spring.security.authentication;

import java.security.SecureRandom;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.token.Sha512DigestUtils;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.web.authentication.rememberme.CookieTheftException;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import io.github.spring.security.core.token.CredentialToken;
import io.github.spring.security.core.token.DefaultCredentialToken;

/**
 * In memory implementation of AuthenticationTokenService. An implementation
 * should rely on Spring Vault for instance.
 */
public class CredentialVaultTokenService implements AuthenticationTokenService<CredentialToken>, InitializingBean {

	private String secret;
	private SecureRandom random;
	private TextEncryptor encryptor;

	private Map<String, CredentialToken> store = new ConcurrentHashMap<String, CredentialToken>();

	private final int SERVER_PSEUDO_INTEGER;

	public CredentialVaultTokenService(String secret) {
		this.secret = secret;
		this.random = new SecureRandom();
		SERVER_PSEUDO_INTEGER = random.nextInt();
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(encryptor, "TextEncryptor requried");
	}

	public void setEncryptor(TextEncryptor encryptor) {
		this.encryptor = encryptor;
	}

	@Override
	public String allocate(String credential) {
		Assert.notNull(credential, "credential must be provided");

		String grn = generateRandomNumber();
		long timestamp = new Date().getTime();

		String signature = timestamp + ":" + grn; // + ":" + extended.toString();

		String secret = computeTokenSecret(timestamp);

		String hex = digestTokenSignature(signature + ":" + secret);
		String key = signature + ":" + hex;

		CredentialToken token = new DefaultCredentialToken(key, encryptor.encrypt(credential), timestamp);
		store.put(key, token);
		return key;
	}

	@Override
	public CredentialToken validate(String key) {
		if (StringUtils.isEmpty(key)) {
			throw new InvalidCookieException("Invalid token key provided");
		}

		CredentialToken token = store.get(key);
		if (token == null) {
			throw new InvalidCookieException("Invalid token key provided");
		}

		String[] tokens = key.split(":");
		if (tokens.length < 3) {
			throw new InvalidCookieException("Expected 3 or more tokens but found " + tokens.length);
		}

		String grn = tokens[1];
		long timestamp = decodeTimestamp(tokens[0]);
		String secret = computeTokenSecret(timestamp);

		String signature = timestamp + ":" + grn;

		// Verification
		String received = tokens[tokens.length - 1];
		String expected = digestTokenSignature(signature + ":" + secret);

		if (!equals(expected, received)) {
			throw new CookieTheftException("Key verification failure");
		}

		return new DefaultCredentialToken(key, encryptor.decrypt(token.getCredential()), token.getKeyCreationTime());
	}

	@Override
	public void erase(String key) {
		store.remove(key);
	}

	private long decodeTimestamp(String token) {
		try {
			return Long.decode(token).longValue();
		} catch (NumberFormatException nfe) {
			throw new InvalidCookieException("Invalid timestamp " + token);
		}
	}

	private String generateRandomNumber() {
		byte[] bytes = new byte[32];
		random.nextBytes(bytes);
		return new String(Hex.encode(bytes));
	}

	private String computeTokenSecret(long timestamp) {
		return secret + ":" + (timestamp % SERVER_PSEUDO_INTEGER);
	}

	private String digestTokenSignature(String secret) {
		return Sha512DigestUtils.shaHex(secret);
	}

	/**
	 * Constant time comparison to prevent against timing attacks.
	 * 
	 * @see org.springframework.security.authentication.encoding.PasswordEncoderUtils
	 */
	private static boolean equals(String expected, String received) {
		byte[] expectedBytes = Utf8.encode(expected);
		byte[] receivedBytes = Utf8.encode(received);
		if (expectedBytes.length != receivedBytes.length) {
			return false;
		}

		int result = 0;
		for (int i = 0; i < expectedBytes.length; i++) {
			result |= expectedBytes[i] ^ receivedBytes[i];
		}
		return result == 0;
	}
}
