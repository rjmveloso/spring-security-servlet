package io.github.spring.security.authentication.servlet;

import org.springframework.security.core.AuthenticationException;

public class ServletAuthenticationException extends AuthenticationException {

	private static final long serialVersionUID = 1L;

	public ServletAuthenticationException(String msg) {
		super(msg);
	}

	public ServletAuthenticationException(String msg, Throwable t) {
		super(msg, t);
	}
}
