/*
 * Copyright 2026-2026 the original author or authors.
 */

package io.modelcontextprotocol.spec.auth;

import io.modelcontextprotocol.spec.McpTransportException;

/**
 * Exception thrown when an authorization failure occurs, such as an OAuth 2.0 error,
 * missing or mismatched issuer ('iss') parameter per RFC 9207 / SEP-2468, or state
 * mismatch.
 *
 * @author Model Context Protocol Authors
 */
public class McpAuthorizationException extends McpTransportException {

	private final String errorCode;

	private final String errorDescription;

	public McpAuthorizationException(String message) {
		super(message);
		this.errorCode = null;
		this.errorDescription = null;
	}

	public McpAuthorizationException(String message, Throwable cause) {
		super(message, cause);
		this.errorCode = null;
		this.errorDescription = null;
	}

	public McpAuthorizationException(String errorCode, String errorDescription, String message) {
		super(message != null ? message : errorCode + (errorDescription != null ? ": " + errorDescription : ""));
		this.errorCode = errorCode;
		this.errorDescription = errorDescription;
	}

	public String getErrorCode() {
		return this.errorCode;
	}

	public String getErrorDescription() {
		return this.errorDescription;
	}

}
