package io.github.spring.security.authentication.servlet;

import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthoritiesContainer;
import org.springframework.security.core.authority.mapping.Attributes2GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.MappableAttributesRetriever;
import org.springframework.security.core.authority.mapping.SimpleAttributes2GrantedAuthoritiesMapper;
import org.springframework.security.web.authentication.preauth.j2ee.WebXmlMappableAttributesRetriever;
import org.springframework.util.Assert;

import io.github.spring.security.authentication.GrantedAuthoritiesManager;

public class ServletGrantedAuthorityManager implements InitializingBean, GrantedAuthoritiesManager {

	private MappableAttributesRetriever mappedAttributesRetriever = new WebXmlMappableAttributesRetriever();
	private Attributes2GrantedAuthoritiesMapper attributesAuthoritiesMapper = new SimpleAttributes2GrantedAuthoritiesMapper();

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(mappedAttributesRetriever, "MappableAttributesRetriever required");
		Assert.notNull(attributesAuthoritiesMapper, "Attributes2GrantedAuthoritiesMapper required");
	}

	protected Collection<String> getUserRoles(HttpServletRequest request) {
		return mappedAttributesRetriever.getMappableAttributes().stream().filter(request::isUserInRole)
				.collect(Collectors.toList());
	}

	@Override
	public GrantedAuthoritiesContainer getGrantedAuthorities(HttpServletRequest request) {
		Collection<? extends GrantedAuthority> authorities = getUserAuthorities(request);
		return () -> Collections.unmodifiableCollection(authorities);
	}

	private Collection<? extends GrantedAuthority> getUserAuthorities(HttpServletRequest request) {
		Collection<String> roles = getUserRoles(request);
		return attributesAuthoritiesMapper.getGrantedAuthorities(roles);
	}

	public void setMappedAttributesRetriever(MappableAttributesRetriever mappedAttributesRetriever) {
		this.mappedAttributesRetriever = mappedAttributesRetriever;
	}

	public void setAttributesAuthoritiesMapper(Attributes2GrantedAuthoritiesMapper attributesAuthoritiesMapper) {
		this.attributesAuthoritiesMapper = attributesAuthoritiesMapper;
	}

}
