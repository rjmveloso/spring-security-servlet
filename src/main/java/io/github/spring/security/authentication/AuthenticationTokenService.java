package io.github.spring.security.authentication;

public interface AuthenticationTokenService<T> {

	/**
	 * @param data
	 *            data to be processed by a specific implementation
	 * @return a new token
	 */
	String allocate(String data);

	T validate(String key);

	void erase(String key);

}
