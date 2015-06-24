package org.security.muralla.model.base;

public class AccessTokenRegistry {
	private Long id;
	private String nonce;
	private String timestamp;
	private String version;
	private String signatureMethod;
	private String consumerKey;
	private String requestToken;
	private String accessToken;
	private String tokenSecret;
	private String verifier;
	private String signature;

	public AccessTokenRegistry() {
	}

	public AccessTokenRegistry(String nonce, String timestamp, String version,
			String signatureMethod, String consumerKey, String requestToken,
			String tokenSecret, String verifier, String signature,
			String accessToken) {
		this.nonce = nonce;
		this.timestamp = timestamp;
		this.version = version;
		this.signatureMethod = signatureMethod;
		this.consumerKey = consumerKey;
		this.requestToken = requestToken;
		this.tokenSecret = tokenSecret;
		this.verifier = verifier;
		this.signature = signature;
		this.accessToken = accessToken;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getNonce() {
		return nonce;
	}

	public void setNonce(String nonce) {
		this.nonce = nonce;
	}

	public String getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getSignatureMethod() {
		return signatureMethod;
	}

	public void setSignatureMethod(String signatureMethod) {
		this.signatureMethod = signatureMethod;
	}

	public String getConsumerKey() {
		return consumerKey;
	}

	public void setConsumerKey(String consumerKey) {
		this.consumerKey = consumerKey;
	}

	public String getRequestToken() {
		return requestToken;
	}

	public void setRequestToken(String requestToken) {
		this.requestToken = requestToken;
	}

	public String getTokenSecret() {
		return tokenSecret;
	}

	public void setTokenSecret(String tokenSecret) {
		this.tokenSecret = tokenSecret;
	}

	public String getVerifier() {
		return verifier;
	}

	public void setVerifier(String verifier) {
		this.verifier = verifier;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
}
