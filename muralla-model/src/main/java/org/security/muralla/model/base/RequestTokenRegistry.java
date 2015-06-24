package org.security.muralla.model.base;


public class RequestTokenRegistry {

	private Long id;
	private String nonce;
	private String timestamp;
	private String callback;
	private String signature;
	private String version;
	private String signatureMethod;
	private String consumerKey;
	private String token;
	private String tokenSecret;

	public RequestTokenRegistry() {
	}

	public RequestTokenRegistry(String nonce, String timestamp,
			String callback, String signature, String version,
			String signatureMethod, String consumerKey, String token,
			String tokenSecret) {
		this.nonce = nonce;
		this.timestamp = timestamp;
		this.callback = callback;
		this.signature = signature;
		this.version = version;
		this.signatureMethod = signatureMethod;
		this.consumerKey = consumerKey;
		this.token = token;
		this.tokenSecret = tokenSecret;
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

	public String getCallback() {
		return callback;
	}

	public void setCallback(String callback) {
		this.callback = callback;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
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

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getTokenSecret() {
		return tokenSecret;
	}

	public void setTokenSecret(String tokenSecret) {
		this.tokenSecret = tokenSecret;
	}
}
