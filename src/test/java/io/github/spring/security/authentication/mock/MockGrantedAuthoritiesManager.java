package io.github.spring.security.authentication.mock;

import java.util.Arrays;
import java.util.HashSet;

import org.springframework.security.core.authority.mapping.SimpleMappableAttributesRetriever;

import io.github.spring.security.authentication.servlet.ServletGrantedAuthorityManager;

public class MockGrantedAuthoritiesManager extends ServletGrantedAuthorityManager {

	private SimpleMappableAttributesRetriever retriever = new SimpleMappableAttributesRetriever();

	public MockGrantedAuthoritiesManager() {
		setMappedAttributesRetriever(retriever);
	}

	public void setUserRoles(String... roles) {
		retriever.setMappableAttributes(new HashSet<String>(Arrays.asList(roles)));
	}

}
