package io.github.spring.security.session;

import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;

public interface SessionDestroyedHandler {

	void handle(HttpSession session, Authentication authentication);
	
}
