package io.github.spring.security.authentication.mock;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.springframework.mock.web.MockHttpServletRequest;

public class MockHttpServlet3Request extends MockHttpServletRequest {

	@Override
	public void login(String username, String password) throws ServletException {
	}

	@Override
	public boolean authenticate(HttpServletResponse response) throws IOException, ServletException {
		return true;
	}

}
