package io.github.spring.security.authentication;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.authority.GrantedAuthoritiesContainer;

public interface GrantedAuthoritiesManager {

	GrantedAuthoritiesContainer getGrantedAuthorities(HttpServletRequest request);

}
