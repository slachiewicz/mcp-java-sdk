/*
 * Copyright 2026-2026 the original author or authors.
 */

package io.modelcontextprotocol.client.auth;

import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.modelcontextprotocol.util.Assert;

/**
 * Represents client registration credentials bound to a specific authorization server per
 * SEP-2352.
 *
 * @param issuer The authorization server issuer identifier URL this registration is bound
 * to
 * @param clientId The client identifier issued by the authorization server
 * @param clientSecret The client secret (optional, for confidential clients)
 * @param scopes Scopes granted or requested for this client registration
 * @param registrationClientUri The client configuration endpoint URI (RFC 7592)
 * @param registrationAccessToken The client registration access token (RFC 7592)
 * @author Model Context Protocol Authors
 */
@JsonInclude(JsonInclude.Include.NON_ABSENT)
public record OAuth2ClientRegistration(@JsonProperty("issuer") String issuer,
		@JsonProperty("client_id") String clientId, @JsonProperty("client_secret") String clientSecret,
		@JsonProperty("scopes") List<String> scopes,
		@JsonProperty("registration_client_uri") String registrationClientUri,
		@JsonProperty("registration_access_token") String registrationAccessToken) {

	@JsonCreator
	public OAuth2ClientRegistration {
		Assert.notNull(issuer, "issuer must not be null");
		Assert.notNull(clientId, "clientId must not be null");
		scopes = scopes != null ? Collections.unmodifiableList(scopes) : Collections.emptyList();
	}

	public static Builder builder(String issuer, String clientId) {
		return new Builder(issuer, clientId);
	}

	public static final class Builder {

		private final String issuer;

		private final String clientId;

		private String clientSecret;

		private List<String> scopes;

		private String registrationClientUri;

		private String registrationAccessToken;

		public Builder(String issuer, String clientId) {
			Assert.notNull(issuer, "issuer must not be null");
			Assert.notNull(clientId, "clientId must not be null");
			this.issuer = issuer;
			this.clientId = clientId;
		}

		public Builder clientSecret(String clientSecret) {
			this.clientSecret = clientSecret;
			return this;
		}

		public Builder scopes(List<String> scopes) {
			this.scopes = scopes;
			return this;
		}

		public Builder registrationClientUri(String registrationClientUri) {
			this.registrationClientUri = registrationClientUri;
			return this;
		}

		public Builder registrationAccessToken(String registrationAccessToken) {
			this.registrationAccessToken = registrationAccessToken;
			return this;
		}

		public OAuth2ClientRegistration build() {
			return new OAuth2ClientRegistration(this.issuer, this.clientId, this.clientSecret, this.scopes,
					this.registrationClientUri, this.registrationAccessToken);
		}

	}

}
