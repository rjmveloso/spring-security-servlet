package io.github.spring.security.authentication;

public interface AuthenticationTokenService<T> {

	/**
	 * @param data
	 *            data to be processed by a specific implementation
	 * @return a new token
	 */
	public String allocate(String data);

	public T validate(String key);

	public void erase(String key);

}
