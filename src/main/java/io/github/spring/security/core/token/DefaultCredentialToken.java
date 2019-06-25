package io.github.spring.security.core.token;

public class DefaultCredentialToken implements CredentialToken {

	private String key;
	private long timestamp;
	private String credential;
	private String extendedInformation;

	public DefaultCredentialToken(String key, String credential, long timestamp) {
		this.key = key;
		this.timestamp = timestamp;
		this.credential = credential;
	}

	@Override
	public String getKey() {
		return key;
	}

	@Override
	public String getCredential() {
		return credential;
	}

	@Override
	public long getKeyCreationTime() {
		return timestamp;
	}

	@Override
	public String getExtendedInformation() {
		return extendedInformation;
	}

	public void setExtendedInformation(String extendedInformation) {
		this.extendedInformation = extendedInformation;
	}

}
