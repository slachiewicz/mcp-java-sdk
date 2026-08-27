/*
 * Copyright 2026-2026 the original author or authors.
 */

package io.modelcontextprotocol.client.auth;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import io.modelcontextprotocol.util.Assert;

/**
 * Thread-safe, in-memory implementation of {@link OAuth2CredentialStore} enforcing
 * issuer-bound credential and token storage per SEP-2352.
 *
 * @author Model Context Protocol Authors
 */
public class InMemoryOAuth2CredentialStore implements OAuth2CredentialStore {

	private final Map<String, OAuth2AccessToken> tokenStore = new ConcurrentHashMap<>();

	private final Map<String, OAuth2ClientRegistration> registrationStore = new ConcurrentHashMap<>();

	@Override
	public void saveToken(String issuer, OAuth2AccessToken token) {
		Assert.notNull(issuer, "issuer must not be null");
		Assert.notNull(token, "token must not be null");
		this.tokenStore.put(normalizeIssuer(issuer), token);
	}

	@Override
	public Optional<OAuth2AccessToken> getToken(String issuer) {
		if (issuer == null) {
			return Optional.empty();
		}
		OAuth2AccessToken token = this.tokenStore.get(normalizeIssuer(issuer));
		if (token != null && token.isExpired()) {
			this.tokenStore.remove(normalizeIssuer(issuer));
			return Optional.empty();
		}
		return Optional.ofNullable(token);
	}

	@Override
	public void removeToken(String issuer) {
		if (issuer != null) {
			this.tokenStore.remove(normalizeIssuer(issuer));
		}
	}

	@Override
	public void saveClientRegistration(String issuer, OAuth2ClientRegistration registration) {
		Assert.notNull(issuer, "issuer must not be null");
		Assert.notNull(registration, "registration must not be null");
		this.registrationStore.put(normalizeIssuer(issuer), registration);
	}

	@Override
	public Optional<OAuth2ClientRegistration> getClientRegistration(String issuer) {
		if (issuer == null) {
			return Optional.empty();
		}
		return Optional.ofNullable(this.registrationStore.get(normalizeIssuer(issuer)));
	}

	@Override
	public void removeClientRegistration(String issuer) {
		if (issuer != null) {
			this.registrationStore.remove(normalizeIssuer(issuer));
		}
	}

	@Override
	public void clear() {
		this.tokenStore.clear();
		this.registrationStore.clear();
	}

	public int size() {
		return this.tokenStore.size() + this.registrationStore.size();
	}

	private static String normalizeIssuer(String issuer) {
		if (issuer == null) {
			return "";
		}
		String trimmed = issuer.trim();
		if (trimmed.endsWith("/")) {
			return trimmed.substring(0, trimmed.length() - 1);
		}
		return trimmed;
	}

}
