package org.security.muralla.model.base;

import java.util.List;

public class AuthenticatedTokenRegistry {

	private Long id;
	private String consumerKey;
	private String username;
	private String timestamp;
	private String nonce;
	private String verifier;
	private String token;
	private List<String> roles;

	public AuthenticatedTokenRegistry() {
	}

	public AuthenticatedTokenRegistry(String consumerKey, String username,
			String timestamp, String nonce, String verifier, String token,
			List<String> roles) {
		this.consumerKey = consumerKey;
		this.username = username;
		this.timestamp = timestamp;
		this.nonce = nonce;
		this.verifier = verifier;
		this.token = token;
		this.roles = roles;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getConsumerKey() {
		return consumerKey;
	}

	public void setConsumerKey(String consumerKey) {
		this.consumerKey = consumerKey;
	}

	public String getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}

	public String getNonce() {
		return nonce;
	}

	public void setNonce(String nonce) {
		this.nonce = nonce;
	}

	public String getVerifier() {
		return verifier;
	}

	public void setVerifier(String verifier) {
		this.verifier = verifier;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public List<String> getRoles() {
		return roles;
	}

	public void setRoles(List<String> roles) {
		this.roles = roles;
	}
}
