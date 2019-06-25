package io.github.spring.security.authentication.servlet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.github.spring.security.authentication.mock.MockHttpServlet3Request;
import io.github.spring.security.authentication.servlet.Authenticator;
import io.github.spring.security.authentication.servlet.HttpServlet3Authenticator;
import io.github.spring.security.authentication.servlet.ServletAuthenticationException;
import io.github.spring.security.authentication.servlet.ServletAuthenticationProvider;
import io.github.spring.security.authentication.mock.MockGrantedAuthoritiesManager;

public class ServletAuthenticationProviderTest {

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
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null);

		ServletAuthenticationProvider provider = new ServletAuthenticationProvider();
		provider.setAuthenticator(new HttpServlet3Authenticator(grantedAuthoritiesManager));
		provider.afterPropertiesSet();

		Authentication result = provider.authenticate(token);

		assertThat(result.getAuthorities()).hasSize(1);
		//assertThat(result.getAuthorities()).contains(new SimpleGrantedAuthority("ROLE_ONE"));
	}

	@Test(expected = ServletAuthenticationException.class)
	public void testInvalidAuthenticate() throws Exception {
		Authenticator authenticator = mock(Authenticator.class);
		when(authenticator.authenticate(any(), any(), any())).thenThrow(ServletAuthenticationException.class);

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null);

		ServletAuthenticationProvider provider = new ServletAuthenticationProvider();
		provider.setAuthenticator(authenticator);
		provider.afterPropertiesSet();

		Authentication result = provider.authenticate(token);
		fail("Should not return: %s", result);
	}

}
