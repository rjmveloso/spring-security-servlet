package io.github.spring.security.authentication.servlet;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class ServletRememberMeAuthenticationProvider extends RememberMeAuthenticationProvider implements InitializingBean {

	private Authenticator authenticator;

	//	private boolean eraseCredentialsAfterAuthentication = true;

	public ServletRememberMeAuthenticationProvider(String key) {
		super(key);
	}

	@Override
	public void afterPropertiesSet() {
		super.afterPropertiesSet();
		Assert.notNull(authenticator, "Authenticator delegate required");
	}

	public void setAuthenticator(Authenticator authenticator) {
		this.authenticator = authenticator;
	}

	//	public void setEraseCredentialsAfterAuthentication(boolean eraseCredentialsAfterAuthentication) {
	//		this.eraseCredentialsAfterAuthentication = eraseCredentialsAfterAuthentication;
	//	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if ((authentication = super.authenticate(authentication)) == null) {
			return null;
		}

		ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
		authentication = authenticator.authenticate(authentication, attributes.getRequest(), attributes.getResponse());

		authentication = new RememberMeAuthenticationToken(getKey(), authentication.getPrincipal(), authentication.getAuthorities());

		//		if (eraseCredentialsAfterAuthentication && (authentication instanceof CredentialsContainer)) {
		//			((CredentialsContainer) authentication).eraseCredentials();
		//		}

		return authentication;
	}
}
