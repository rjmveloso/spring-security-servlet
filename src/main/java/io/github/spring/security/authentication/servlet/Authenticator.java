package io.github.spring.security.authentication.servlet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;

public interface Authenticator {

	public Authentication authenticate(Authentication authentication, HttpServletRequest request, HttpServletResponse response);

}
