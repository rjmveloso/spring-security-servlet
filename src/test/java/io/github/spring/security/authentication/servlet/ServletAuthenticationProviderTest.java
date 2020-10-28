package io.github.spring.security.authentication.servlet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.github.spring.security.authentication.mock.MockGrantedAuthoritiesManager;
import io.github.spring.security.authentication.mock.MockHttpServlet3Request;

public class ServletAuthenticationProviderTest {

	private MockGrantedAuthoritiesManager grantedAuthoritiesManager;

	@BeforeEach
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
		assertThat(result.getAuthorities()).extracting(GrantedAuthority::getAuthority).contains("ROLE_ONE");
	}

	@Test
	public void testInvalidAuthenticate() throws Exception {
		Authenticator authenticator = mock(Authenticator.class);
		when(authenticator.authenticate(any(), any(), any())).thenThrow(ServletAuthenticationException.class);

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null);

		ServletAuthenticationProvider provider = new ServletAuthenticationProvider();
		provider.setAuthenticator(authenticator);
		provider.afterPropertiesSet();

		assertThatThrownBy(() -> provider.authenticate(token)).isInstanceOf(ServletAuthenticationException.class);
	}

}
