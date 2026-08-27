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
 * Represents OAuth 2.0 Authorization Server Metadata per RFC 8414, including support for
 * RFC 9207 / SEP-2468 {@code authorization_response_iss_parameter_supported}.
 *
 * @param issuer The authorization server's issuer identifier URL (mandatory)
 * @param authorizationEndpoint URL of the authorization endpoint
 * @param tokenEndpoint URL of the token endpoint
 * @param registrationEndpoint URL of the dynamic client registration endpoint (RFC 7591)
 * @param jwksUri URL of the authorization server's JWK Set document
 * @param scopesSupported List of OAuth 2.0 scope values supported
 * @param responseTypesSupported List of OAuth 2.0 response_type values supported
 * @param grantTypesSupported List of OAuth 2.0 grant_type values supported
 * @param tokenEndpointAuthMethodsSupported List of client authentication methods
 * supported
 * @param authorizationResponseIssParameterSupported Boolean parameter indicating whether
 * the authorization server supports the {@code iss} response parameter (RFC 9207 /
 * SEP-2468)
 * @author Model Context Protocol Authors
 */
@JsonInclude(JsonInclude.Include.NON_ABSENT)
public record OAuth2AuthorizationServerMetadata(@JsonProperty("issuer") String issuer,
		@JsonProperty("authorization_endpoint") String authorizationEndpoint,
		@JsonProperty("token_endpoint") String tokenEndpoint,
		@JsonProperty("registration_endpoint") String registrationEndpoint, @JsonProperty("jwks_uri") String jwksUri,
		@JsonProperty("scopes_supported") List<String> scopesSupported,
		@JsonProperty("response_types_supported") List<String> responseTypesSupported,
		@JsonProperty("grant_types_supported") List<String> grantTypesSupported,
		@JsonProperty("token_endpoint_auth_methods_supported") List<String> tokenEndpointAuthMethodsSupported,
		@JsonProperty("authorization_response_iss_parameter_supported") Boolean authorizationResponseIssParameterSupported) {

	@JsonCreator
	public OAuth2AuthorizationServerMetadata {
		Assert.notNull(issuer, "issuer must not be null");
		scopesSupported = scopesSupported != null ? Collections.unmodifiableList(scopesSupported) : null;
		responseTypesSupported = responseTypesSupported != null ? Collections.unmodifiableList(responseTypesSupported)
				: null;
		grantTypesSupported = grantTypesSupported != null ? Collections.unmodifiableList(grantTypesSupported) : null;
		tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported != null
				? Collections.unmodifiableList(tokenEndpointAuthMethodsSupported) : null;
	}

	public static Builder builder(String issuer) {
		return new Builder(issuer);
	}

	public static final class Builder {

		private final String issuer;

		private String authorizationEndpoint;

		private String tokenEndpoint;

		private String registrationEndpoint;

		private String jwksUri;

		private List<String> scopesSupported;

		private List<String> responseTypesSupported;

		private List<String> grantTypesSupported;

		private List<String> tokenEndpointAuthMethodsSupported;

		private Boolean authorizationResponseIssParameterSupported = Boolean.TRUE;

		public Builder(String issuer) {
			Assert.notNull(issuer, "issuer must not be null");
			this.issuer = issuer;
		}

		public Builder authorizationEndpoint(String authorizationEndpoint) {
			this.authorizationEndpoint = authorizationEndpoint;
			return this;
		}

		public Builder tokenEndpoint(String tokenEndpoint) {
			this.tokenEndpoint = tokenEndpoint;
			return this;
		}

		public Builder registrationEndpoint(String registrationEndpoint) {
			this.registrationEndpoint = registrationEndpoint;
			return this;
		}

		public Builder jwksUri(String jwksUri) {
			this.jwksUri = jwksUri;
			return this;
		}

		public Builder scopesSupported(List<String> scopesSupported) {
			this.scopesSupported = scopesSupported;
			return this;
		}

		public Builder responseTypesSupported(List<String> responseTypesSupported) {
			this.responseTypesSupported = responseTypesSupported;
			return this;
		}

		public Builder grantTypesSupported(List<String> grantTypesSupported) {
			this.grantTypesSupported = grantTypesSupported;
			return this;
		}

		public Builder tokenEndpointAuthMethodsSupported(List<String> tokenEndpointAuthMethodsSupported) {
			this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
			return this;
		}

		public Builder authorizationResponseIssParameterSupported(Boolean authorizationResponseIssParameterSupported) {
			this.authorizationResponseIssParameterSupported = authorizationResponseIssParameterSupported;
			return this;
		}

		public OAuth2AuthorizationServerMetadata build() {
			return new OAuth2AuthorizationServerMetadata(this.issuer, this.authorizationEndpoint, this.tokenEndpoint,
					this.registrationEndpoint, this.jwksUri, this.scopesSupported, this.responseTypesSupported,
					this.grantTypesSupported, this.tokenEndpointAuthMethodsSupported,
					this.authorizationResponseIssParameterSupported);
		}

	}

}
