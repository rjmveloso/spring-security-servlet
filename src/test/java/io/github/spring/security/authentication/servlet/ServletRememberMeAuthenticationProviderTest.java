package io.github.spring.security.authentication.servlet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.github.spring.security.authentication.mock.MockGrantedAuthoritiesManager;
import io.github.spring.security.authentication.mock.MockHttpServlet3Request;
import io.github.spring.security.authentication.servlet.Authenticator;
import io.github.spring.security.authentication.servlet.HttpServlet3Authenticator;
import io.github.spring.security.authentication.servlet.ServletAuthenticationException;
import io.github.spring.security.authentication.servlet.ServletRememberMeAuthenticationProvider;

public class ServletRememberMeAuthenticationProviderTest {

	private static final String KEY = "key";

	private MockGrantedAuthoritiesManager grantedAuthoritiesManager;

	@Before
	public void init() {
		grantedAuthoritiesManager = new MockGrantedAuthoritiesManager();
		grantedAuthoritiesManager.setUserRoles("ROLE_ONE", "ROLE_TWO");

		MockHttpServletRequest request = new MockHttpServlet3Request();
		request.addUserRole("ROLE_ONE");

		RequestAttributes attributes = new ServletRequestAttributes(request);
		RequestContextHolder.setRequestAttributes(attributes);
	}

	@Test
	public void testValidAuthenticate() throws Exception {
		Authenticator authenticator = new HttpServlet3Authenticator(grantedAuthoritiesManager);

		RememberMeAuthenticationToken token = new RememberMeAuthenticationToken(KEY, "user", null);

		ServletRememberMeAuthenticationProvider provider = new ServletRememberMeAuthenticationProvider(KEY);
		provider.setAuthenticator(authenticator);
		provider.afterPropertiesSet();

		Authentication result = provider.authenticate(token);

		assertThat(result.getAuthorities()).hasSize(1);
		// assertThat(result.getAuthorities()).contains(new SimpleGrantedAuthority("ROLE_ONE"));
	}

	@Test(expected = ServletAuthenticationException.class)
	public void testInvalidAuthenticate() throws Exception {
		Authenticator authenticator = mock(Authenticator.class);
		when(authenticator.authenticate(any(), any(), any())).thenThrow(ServletAuthenticationException.class);

		RememberMeAuthenticationToken token = new RememberMeAuthenticationToken(KEY, "user", null);

		ServletRememberMeAuthenticationProvider provider = new ServletRememberMeAuthenticationProvider(KEY);
		provider.setAuthenticator(authenticator);
		provider.afterPropertiesSet();

		Authentication result = provider.authenticate(token);
		fail("Should not return: %s", result);
	}

}
