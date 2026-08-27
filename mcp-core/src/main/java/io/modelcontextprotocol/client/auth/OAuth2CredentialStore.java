/*
 * Copyright 2026-2026 the original author or authors.
 */

package io.modelcontextprotocol.client.auth;

import java.util.Optional;

/**
 * Storage SPI for OAuth 2.0 client credentials and access tokens, enforcing strict issuer
 * binding per SEP-2352.
 * <p>
 * Under SEP-2352, client registrations and access tokens MUST be bound to the specific
 * authorization server (issuer) that issued them and must never be reused across
 * different issuers.
 *
 * @author Model Context Protocol Authors
 */
public interface OAuth2CredentialStore {

	/**
	 * Store an access token bound to the given authorization server issuer.
	 * @param issuer The authorization server issuer identifier URL
	 * @param token The access token to store
	 */
	void saveToken(String issuer, OAuth2AccessToken token);

	/**
	 * Retrieve the access token bound to the specified issuer.
	 * @param issuer The authorization server issuer identifier URL
	 * @return Optional containing the access token if present and valid
	 */
	Optional<OAuth2AccessToken> getToken(String issuer);

	/**
	 * Remove stored tokens for the given issuer.
	 * @param issuer The authorization server issuer identifier URL
	 */
	void removeToken(String issuer);

	/**
	 * Store client registration credentials bound to the given authorization server
	 * issuer.
	 * @param issuer The authorization server issuer identifier URL
	 * @param registration The client registration credentials
	 */
	void saveClientRegistration(String issuer, OAuth2ClientRegistration registration);

	/**
	 * Retrieve client registration credentials bound to the given issuer.
	 * @param issuer The authorization server issuer identifier URL
	 * @return Optional containing the client registration if present
	 */
	Optional<OAuth2ClientRegistration> getClientRegistration(String issuer);

	/**
	 * Remove stored client registration for the given issuer.
	 * @param issuer The authorization server issuer identifier URL
	 */
	void removeClientRegistration(String issuer);

	/**
	 * Clear all stored credentials and tokens across all issuers.
	 */
	void clear();

}
