/*
 * Copyright 2026-2026 the original author or authors.
 */

package io.modelcontextprotocol.spec.auth;

import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.modelcontextprotocol.util.Assert;

/**
 * Represents OAuth 2.0 Protected Resource Metadata per RFC 9728. MCP servers expose this
 * metadata to indicate the resource identifier, the authorization servers that protect
 * this resource, supported scopes, and bearer methods.
 *
 * @param resource The resource identifier URI
 * @param authorizationServers List of authorization server issuer URIs
 * @param scopesSupported List of OAuth 2.0 scopes supported by this protected resource
 * @param bearerMethodsSupported List of bearer token transmission methods supported
 * @param resourceDocumentation URL pointing to human-readable documentation for the
 * resource
 * @author Model Context Protocol Authors
 */
@JsonInclude(JsonInclude.Include.NON_ABSENT)
public record OAuth2ProtectedResourceMetadata(@JsonProperty("resource") String resource,
		@JsonProperty("authorization_servers") List<String> authorizationServers,
		@JsonProperty("scopes_supported") List<String> scopesSupported,
		@JsonProperty("bearer_methods_supported") List<String> bearerMethodsSupported,
		@JsonProperty("resource_documentation") String resourceDocumentation) {

	@JsonCreator
	public OAuth2ProtectedResourceMetadata {
		authorizationServers = authorizationServers != null ? Collections.unmodifiableList(authorizationServers)
				: Collections.emptyList();
		scopesSupported = scopesSupported != null ? Collections.unmodifiableList(scopesSupported) : null;
		bearerMethodsSupported = bearerMethodsSupported != null ? Collections.unmodifiableList(bearerMethodsSupported)
				: null;
	}

	public static Builder builder(String resource) {
		return new Builder(resource);
	}

	public static final class Builder {

		private final String resource;

		private List<String> authorizationServers;

		private List<String> scopesSupported;

		private List<String> bearerMethodsSupported;

		private String resourceDocumentation;

		public Builder(String resource) {
			Assert.notNull(resource, "resource must not be null");
			this.resource = resource;
		}

		public Builder authorizationServers(List<String> authorizationServers) {
			this.authorizationServers = authorizationServers;
			return this;
		}

		public Builder scopesSupported(List<String> scopesSupported) {
			this.scopesSupported = scopesSupported;
			return this;
		}

		public Builder bearerMethodsSupported(List<String> bearerMethodsSupported) {
			this.bearerMethodsSupported = bearerMethodsSupported;
			return this;
		}

		public Builder resourceDocumentation(String resourceDocumentation) {
			this.resourceDocumentation = resourceDocumentation;
			return this;
		}

		public OAuth2ProtectedResourceMetadata build() {
			return new OAuth2ProtectedResourceMetadata(this.resource, this.authorizationServers, this.scopesSupported,
					this.bearerMethodsSupported, this.resourceDocumentation);
		}

	}

}
