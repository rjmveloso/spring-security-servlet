package io.github.spring.security.authentication.servlet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;
import org.springframework.util.Assert;

import io.github.spring.security.authentication.AuthenticationTokenService;
import io.github.spring.security.core.token.CredentialToken;

public class ServletRememberMeAuthenticationServices extends AbstractRememberMeServices implements InitializingBean {

	private AuthenticationTokenService<CredentialToken> authenticationTokenService;

	public ServletRememberMeAuthenticationServices(String key) {
		super(key, new UserDetailsServiceAccessor());
	}

	@Override
	public void afterPropertiesSet() {
		super.afterPropertiesSet();
		Assert.notNull(authenticationTokenService, "AuthenticationTokenService required");
	}

	public void setUserDetailsTokenService(AuthenticationTokenService<CredentialToken> authenticationTokenService) {
		this.authenticationTokenService = authenticationTokenService;
	}

	@Override
	public void onLoginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		String username = authentication.getName();
		String password = (String) authentication.getCredentials();
		String key = authenticationTokenService.allocate(password);
		setCookie(new String[] { username, key }, getTokenValiditySeconds(), request, response);
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		super.logout(request, response, authentication);
		eraseToken(request);
	}

	@Override
	protected void onLoginFail(HttpServletRequest request, HttpServletResponse response) {
		super.onLoginFail(request, response);
		eraseToken(request);
	}

	protected void eraseToken(HttpServletRequest request) {
		String rememberMeCookie = extractRememberMeCookie(request);

		if (rememberMeCookie == null || rememberMeCookie.length() == 0) {
			return;
		}

		try {
			String[] cookieTokens = decodeCookie(rememberMeCookie);
			authenticationTokenService.erase(cookieTokens[1]);
		} catch (InvalidCookieException e) {
			logger.debug("Invalid remember-me cookie: " + e.getMessage());
		}
	}

	@Override
	protected Authentication createSuccessfulAuthentication(HttpServletRequest request, UserDetails user) {
		Authentication authentication = super.createSuccessfulAuthentication(request, user);
		authentication.setAuthenticated(false);
		return authentication;
	}

	@Override
	protected UserDetails processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request, HttpServletResponse response)
			throws RememberMeAuthenticationException, UsernameNotFoundException {
		CredentialToken token = authenticationTokenService.validate(cookieTokens[1]);
		return new User(cookieTokens[0], token.getCredential(), AuthorityUtils.NO_AUTHORITIES);
	}

	private static final class UserDetailsServiceAccessor implements UserDetailsService {
		@Override
		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
			return null;
		}
	};
}
