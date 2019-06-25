package io.github.spring.security.session;

import java.util.Objects;

import javax.servlet.http.HttpSession;

import org.springframework.context.ApplicationListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionDestroyedEvent;

public class SessionDestroyedListener implements ApplicationListener<SessionDestroyedEvent> {

	private SessionDestroyedHandler sthandler = new SessionDestroyedHandler() {
		@Override
		public void handle(HttpSession session, Authentication authentication) {
		}
	};

	public void setSessionTimeoutHandler(SessionDestroyedHandler handler) {
		Objects.requireNonNull(handler);
		this.sthandler = handler;
	}

	@Override
	public void onApplicationEvent(SessionDestroyedEvent event) {
		final HttpSession session = (HttpSession) event.getSource();

		for (SecurityContext context : event.getSecurityContexts()) {
			handleSessionTimeout(session, context);
		}
	}

	private void handleSessionTimeout(HttpSession session, SecurityContext context) {
		Authentication authentication = context.getAuthentication();

		try {
			SecurityContextHolder.setContext(context);

			sthandler.handle(session, authentication);
		} finally {
			SecurityContextHolder.clearContext();
		}
	}
}
