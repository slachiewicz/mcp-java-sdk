/*
 * Copyright 2026-2026 the original author or authors.
 */

package io.modelcontextprotocol.client.auth;

import java.time.Instant;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.modelcontextprotocol.util.Assert;

/**
 * Represents an OAuth 2.0 Access Token with expiration and scope metadata.
 *
 * @param tokenValue The access token string value
 * @param tokenType The token type (e.g., "Bearer")
 * @param expiresAt The timestamp when the token expires (optional)
 * @param scope Space-delimited scope string or scope set (optional)
 * @param refreshToken Optional refresh token string
 * @author Model Context Protocol Authors
 */
@JsonInclude(JsonInclude.Include.NON_ABSENT)
public record OAuth2AccessToken(@JsonProperty("access_token") String tokenValue,
		@JsonProperty("token_type") String tokenType, @JsonProperty("expires_at") Instant expiresAt,
		@JsonProperty("scope") String scope, @JsonProperty("refresh_token") String refreshToken) {

	@JsonCreator
	public OAuth2AccessToken {
		Assert.notNull(tokenValue, "tokenValue must not be null");
		if (tokenType == null) {
			tokenType = "Bearer";
		}
	}

	public boolean isExpired() {
		return this.expiresAt != null && Instant.now().isAfter(this.expiresAt);
	}

	public static Builder builder(String tokenValue) {
		return new Builder(tokenValue);
	}

	public static final class Builder {

		private final String tokenValue;

		private String tokenType = "Bearer";

		private Instant expiresAt;

		private String scope;

		private String refreshToken;

		public Builder(String tokenValue) {
			Assert.notNull(tokenValue, "tokenValue must not be null");
			this.tokenValue = tokenValue;
		}

		public Builder tokenType(String tokenType) {
			this.tokenType = tokenType;
			return this;
		}

		public Builder expiresInSeconds(long seconds) {
			this.expiresAt = Instant.now().plusSeconds(seconds);
			return this;
		}

		public Builder expiresAt(Instant expiresAt) {
			this.expiresAt = expiresAt;
			return this;
		}

		public Builder scope(String scope) {
			this.scope = scope;
			return this;
		}

		public Builder refreshToken(String refreshToken) {
			this.refreshToken = refreshToken;
			return this;
		}

		public OAuth2AccessToken build() {
			return new OAuth2AccessToken(this.tokenValue, this.tokenType, this.expiresAt, this.scope,
					this.refreshToken);
		}

	}

}
