/*
 * Copyright 2026-2026 the original author or authors.
 */

package io.modelcontextprotocol.auth;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.modelcontextprotocol.client.auth.InMemoryOAuth2CredentialStore;
import io.modelcontextprotocol.client.auth.OAuth2AccessToken;
import io.modelcontextprotocol.client.auth.OAuth2ClientRegistration;
import io.modelcontextprotocol.spec.auth.McpAuthorizationException;
import io.modelcontextprotocol.spec.auth.OAuth2AuthorizationResponse;
import io.modelcontextprotocol.spec.auth.OAuth2AuthorizationServerMetadata;
import io.modelcontextprotocol.spec.auth.OAuth2ProtectedResourceMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static io.modelcontextprotocol.util.McpJsonMapperUtils.JSON_MAPPER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for SEP-2468 (RFC 9207 Issuer 'iss' validation in Auth Responses) and SEP-2352
 * (Issuer-bound client credentials and token storage).
 *
 * @author Model Context Protocol Authors
 */
public class OAuth2SecurityTests {

	@Nested
	@DisplayName("SEP-2468 / RFC 9207 Issuer Validation in Authorization Responses")
	class Sep2468IssuerValidationTests {

		@Test
		void validAuthorizationResponseWithMatchingIssuer() {
			String expectedIssuer = "https://auth.example.com";
			String state = "state-xyz-123";
			String code = "authz-code-abc";

			var response = OAuth2AuthorizationResponse.builder().code(code).state(state).iss(expectedIssuer).build();

			OAuth2AuthorizationResponse validated = response.validate(expectedIssuer, state);
			assertThat(validated.code()).isEqualTo(code);
			assertThat(validated.state()).isEqualTo(state);
			assertThat(validated.iss()).isEqualTo(expectedIssuer);
			assertThat(validated.isSuccess()).isTrue();
			assertThat(validated.isError()).isFalse();
		}

		@Test
		void validAuthorizationResponseWithTrailingSlashNormalized() {
			String expectedIssuer = "https://auth.example.com/";
			String responseIssuer = "https://auth.example.com";
			String state = "state-123";

			var response = OAuth2AuthorizationResponse.builder()
				.code("code-123")
				.state(state)
				.iss(responseIssuer)
				.build();

			OAuth2AuthorizationResponse validated = response.validate(expectedIssuer, state);
			assertThat(validated.isSuccess()).isTrue();
		}

		@Test
		void rejectMissingIssuerWhenExpectedPerRfc9207() {
			String expectedIssuer = "https://auth.example.com";
			String state = "state-123";

			var response = OAuth2AuthorizationResponse.builder().code("code-123").state(state).build();

			assertThatThrownBy(() -> response.validate(expectedIssuer, state))
				.isInstanceOf(McpAuthorizationException.class)
				.hasMessageContaining(
						"Missing required 'iss' parameter in authorization response per RFC 9207 / SEP-2468")
				.satisfies(
						ex -> assertThat(((McpAuthorizationException) ex).getErrorCode()).isEqualTo("missing_issuer"));
		}

		@Test
		void rejectMismatchedIssuerToPreventMixUpAttack() {
			String expectedIssuer = "https://legitimate-auth.example.com";
			String attackerIssuer = "https://attacker-auth.example.com";
			String state = "state-123";

			var response = OAuth2AuthorizationResponse.builder()
				.code("code-xyz")
				.state(state)
				.iss(attackerIssuer)
				.build();

			assertThatThrownBy(() -> response.validate(expectedIssuer, state))
				.isInstanceOf(McpAuthorizationException.class)
				.hasMessageContaining("Authorization server issuer mismatch per RFC 9207 / SEP-2468")
				.satisfies(
						ex -> assertThat(((McpAuthorizationException) ex).getErrorCode()).isEqualTo("issuer_mismatch"));
		}

		@Test
		void rejectStateMismatchToPreventCsrf() {
			String expectedIssuer = "https://auth.example.com";

			var response = OAuth2AuthorizationResponse.builder()
				.code("code-xyz")
				.state("received-state-wrong")
				.iss(expectedIssuer)
				.build();

			assertThatThrownBy(() -> response.validate(expectedIssuer, "expected-state-correct"))
				.isInstanceOf(McpAuthorizationException.class)
				.hasMessageContaining("State parameter mismatch in authorization response")
				.satisfies(
						ex -> assertThat(((McpAuthorizationException) ex).getErrorCode()).isEqualTo("invalid_state"));
		}

		@Test
		void rejectErrorResponse() {
			var response = OAuth2AuthorizationResponse.builder()
				.error("access_denied")
				.errorDescription("User denied access")
				.state("state-123")
				.build();

			assertThatThrownBy(() -> response.validate("https://auth.example.com", "state-123"))
				.isInstanceOf(McpAuthorizationException.class)
				.hasMessageContaining("access_denied")
				.satisfies(ex -> {
					McpAuthorizationException authEx = (McpAuthorizationException) ex;
					assertThat(authEx.getErrorCode()).isEqualTo("access_denied");
					assertThat(authEx.getErrorDescription()).isEqualTo("User denied access");
				});
		}

		@Test
		void parseFromRedirectUriWithQuery() {
			URI redirectUri = URI
				.create("http://localhost:8080/callback?code=abc-123&state=xyz-456&iss=https%3A%2F%2Fauth.example.com");

			OAuth2AuthorizationResponse response = OAuth2AuthorizationResponse.fromUri(redirectUri);

			assertThat(response.code()).isEqualTo("abc-123");
			assertThat(response.state()).isEqualTo("xyz-456");
			assertThat(response.iss()).isEqualTo("https://auth.example.com");
			assertThat(response.isSuccess()).isTrue();
		}

		@Test
		void parseFromRedirectUriWithFragment() {
			URI redirectUri = URI
				.create("http://localhost:8080/callback#code=abc-123&state=xyz-456&iss=https%3A%2F%2Fauth.example.com");

			OAuth2AuthorizationResponse response = OAuth2AuthorizationResponse.fromUri(redirectUri);

			assertThat(response.code()).isEqualTo("abc-123");
			assertThat(response.state()).isEqualTo("xyz-456");
			assertThat(response.iss()).isEqualTo("https://auth.example.com");
		}

		@Test
		void parseFromParametersMap() {
			Map<String, String> params = Map.of("code", "auth-code", "state", "state-val", "iss",
					"https://as.example.com");

			OAuth2AuthorizationResponse response = OAuth2AuthorizationResponse.fromParameters(params);
			assertThat(response.code()).isEqualTo("auth-code");
			assertThat(response.state()).isEqualTo("state-val");
			assertThat(response.iss()).isEqualTo("https://as.example.com");
		}

	}

	@Nested
	@DisplayName("RFC 9728 & RFC 8414 Metadata Records Serialization")
	class MetadataSerializationTests {

		@Test
		void protectedResourceMetadataSerialization() throws Exception {
			var metadata = OAuth2ProtectedResourceMetadata.builder("https://mcp.example.com/resource")
				.authorizationServers(List.of("https://auth.example.com"))
				.scopesSupported(List.of("mcp:read", "mcp:write"))
				.bearerMethodsSupported(List.of("header"))
				.resourceDocumentation("https://docs.example.com/api")
				.build();

			String json = JSON_MAPPER.writeValueAsString(metadata);
			assertThat(json).contains("\"resource\":\"https://mcp.example.com/resource\"");
			assertThat(json).contains("\"authorization_servers\":[\"https://auth.example.com\"]");
			assertThat(json).contains("\"scopes_supported\":[\"mcp:read\",\"mcp:write\"]");

			OAuth2ProtectedResourceMetadata read = JSON_MAPPER.readValue(json, OAuth2ProtectedResourceMetadata.class);
			assertThat(read.resource()).isEqualTo("https://mcp.example.com/resource");
			assertThat(read.authorizationServers()).containsExactly("https://auth.example.com");
			assertThat(read.scopesSupported()).containsExactly("mcp:read", "mcp:write");
			assertThat(read.resourceDocumentation()).isEqualTo("https://docs.example.com/api");
		}

		@Test
		void authorizationServerMetadataSerialization() throws Exception {
			var metadata = OAuth2AuthorizationServerMetadata.builder("https://auth.example.com")
				.authorizationEndpoint("https://auth.example.com/oauth/authorize")
				.tokenEndpoint("https://auth.example.com/oauth/token")
				.registrationEndpoint("https://auth.example.com/oauth/register")
				.scopesSupported(List.of("mcp:read", "mcp:write"))
				.authorizationResponseIssParameterSupported(true)
				.build();

			String json = JSON_MAPPER.writeValueAsString(metadata);
			assertThat(json).contains("\"issuer\":\"https://auth.example.com\"");
			assertThat(json).contains("\"authorization_response_iss_parameter_supported\":true");

			OAuth2AuthorizationServerMetadata read = JSON_MAPPER.readValue(json,
					OAuth2AuthorizationServerMetadata.class);
			assertThat(read.issuer()).isEqualTo("https://auth.example.com");
			assertThat(read.authorizationEndpoint()).isEqualTo("https://auth.example.com/oauth/authorize");
			assertThat(read.tokenEndpoint()).isEqualTo("https://auth.example.com/oauth/token");
			assertThat(read.authorizationResponseIssParameterSupported()).isTrue();
		}

	}

	@Nested
	@DisplayName("SEP-2352 Issuer-Bound Credential Store")
	class Sep2352CredentialStoreTests {

		private InMemoryOAuth2CredentialStore store;

		@BeforeEach
		void setUp() {
			this.store = new InMemoryOAuth2CredentialStore();
		}

		@Test
		void tokensBoundToSpecificIssuer() {
			String issuerA = "https://auth-a.example.com";
			String issuerB = "https://auth-b.example.com";

			var tokenA = OAuth2AccessToken.builder("token-a-secret")
				.tokenType("Bearer")
				.expiresInSeconds(3600)
				.scope("tools:read")
				.build();

			this.store.saveToken(issuerA, tokenA);

			// Issuer A retrieves Token A
			Optional<OAuth2AccessToken> retrievedA = this.store.getToken(issuerA);
			assertThat(retrievedA).isPresent();
			assertThat(retrievedA.get().tokenValue()).isEqualTo("token-a-secret");
			assertThat(retrievedA.get().scope()).isEqualTo("tools:read");

			// Issuer B cannot retrieve Token A (strict issuer binding per SEP-2352)
			Optional<OAuth2AccessToken> retrievedB = this.store.getToken(issuerB);
			assertThat(retrievedB).isEmpty();
		}

		@Test
		void clientRegistrationBoundToSpecificIssuer() {
			String issuerA = "https://auth-a.example.com";
			String issuerB = "https://auth-b.example.com";

			var regA = OAuth2ClientRegistration.builder(issuerA, "client-id-a")
				.clientSecret("secret-a")
				.scopes(List.of("tools:read", "resources:read"))
				.build();

			this.store.saveClientRegistration(issuerA, regA);

			assertThat(this.store.getClientRegistration(issuerA)).isPresent();
			assertThat(this.store.getClientRegistration(issuerA).get().clientId()).isEqualTo("client-id-a");

			// Issuer B does not have regA
			assertThat(this.store.getClientRegistration(issuerB)).isEmpty();
		}

		@Test
		void tokenExpirationHandling() {
			String issuer = "https://auth.example.com";
			var expiredToken = OAuth2AccessToken.builder("expired-secret")
				.expiresAt(Instant.now().minusSeconds(10))
				.build();

			this.store.saveToken(issuer, expiredToken);

			assertThat(this.store.getToken(issuer)).isEmpty();
		}

		@Test
		void migrationBetweenAuthorizationServersForcesReRegistration() {
			String oldIssuer = "https://old-auth.example.com";
			String newIssuer = "https://new-auth.example.com";

			var oldToken = OAuth2AccessToken.builder("old-token").expiresInSeconds(3600).build();
			var oldReg = OAuth2ClientRegistration.builder(oldIssuer, "old-client-id").build();

			this.store.saveToken(oldIssuer, oldToken);
			this.store.saveClientRegistration(oldIssuer, oldReg);

			// Client migrates to newIssuer: must not reuse old credentials
			assertThat(this.store.getToken(newIssuer)).isEmpty();
			assertThat(this.store.getClientRegistration(newIssuer)).isEmpty();

			// Fresh registration for newIssuer
			var newReg = OAuth2ClientRegistration.builder(newIssuer, "new-client-id").build();
			var newToken = OAuth2AccessToken.builder("new-token").expiresInSeconds(3600).build();
			this.store.saveClientRegistration(newIssuer, newReg);
			this.store.saveToken(newIssuer, newToken);

			assertThat(this.store.getClientRegistration(newIssuer).get().clientId()).isEqualTo("new-client-id");
			assertThat(this.store.getToken(newIssuer).get().tokenValue()).isEqualTo("new-token");
		}

	}

}
