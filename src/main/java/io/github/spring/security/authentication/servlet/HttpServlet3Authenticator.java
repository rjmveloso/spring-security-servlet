package io.github.spring.security.authentication.servlet;

import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthoritiesContainer;
import org.springframework.security.core.userdetails.UserDetails;

import io.github.spring.security.authentication.GrantedAuthoritiesManager;

/**
 * This class supports authentication based on the new Servlet 3.0
 * {@link javax.servlet.http.HttpServletRequest} <code>login</code> method.
 * 
 * @author ricardo.veloso
 *
 */
final class HttpServlet3Authenticator implements Authenticator {

	private GrantedAuthoritiesManager grantedAuthoritiesManager;

	public HttpServlet3Authenticator(GrantedAuthoritiesManager grantedAuthoritiesManager) {
		this.grantedAuthoritiesManager = grantedAuthoritiesManager;
	}

	private boolean isInstanceOfUserDetails(Object principal) {
		return principal instanceof UserDetails;
	}

	private String retrieveUsername(Authentication authentication) {
		Object principal = authentication.getPrincipal();
		if (isInstanceOfUserDetails(principal)) {
			return ((UserDetails) principal).getUsername();
		} else {
			return principal.toString();
		}
	}

	private String retrievePassword(Authentication authentication) {
		Object principal = authentication.getPrincipal();
		if (isInstanceOfUserDetails(principal)) {
			return ((UserDetails) principal).getPassword();
		} else if (authentication.getCredentials() != null) {
			return authentication.getCredentials().toString();
		}
		return null;
	}

	private boolean isPrincipalAuthenticated(HttpServletRequest request, HttpServletResponse response) {
		//return request.authenticate(response);
		return request.getUserPrincipal() != null;
	}

	@Override
	public Authentication authenticate(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
		String username = retrieveUsername(authentication);
		String password = retrievePassword(authentication);

		try {
			if (!isPrincipalAuthenticated(request, response)) {
				request.login(username, password);
			}
		} catch (ServletException e) {
			throw new ServletAuthenticationException("Authentication failed", e);
		}

		return buildAuthenticationDetails(authentication, request);
	}

	private Authentication buildAuthenticationDetails(Authentication authentication, HttpServletRequest request) {
		GrantedAuthoritiesContainer details = grantedAuthoritiesManager.getGrantedAuthorities(request);
		Collection<? extends GrantedAuthority> authorities = details.getGrantedAuthorities();
		return new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(), authorities);
	}

}
