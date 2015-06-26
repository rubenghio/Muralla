package org.security.muralla.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.security.muralla.model.base.AccessTokenRegistry;

@Entity
@Table(name = "oauth_access_token_registry")
public class AccessTokenRegistryEntity extends AccessTokenRegistry {

	public AccessTokenRegistryEntity() {
	}

	public AccessTokenRegistryEntity(AccessTokenRegistry model) {
		setNonce(model.getNonce());
		setTimestamp(model.getTimestamp());
		setVersion(model.getVersion());
		setSignatureMethod(model.getSignatureMethod());
		setConsumerKey(model.getConsumerKey());
		setRequestToken(model.getRequestToken());
		setTokenSecret(model.getTokenSecret());
		setVerifier(model.getVerifier());
		setSignature(model.getSignature());
		setToken(model.getToken());
	}

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	@Override
	public Long getId() {
		return super.getId();
	}

	@Override
	public String getNonce() {
		return super.getNonce();
	}

	@Override
	public String getTimestamp() {
		return super.getTimestamp();
	}

	@Override
	public String getVersion() {
		return super.getVersion();
	}

	@Override
	@Column(name = "signature_method")
	public String getSignatureMethod() {
		return super.getSignatureMethod();
	}

	@Override
	@Column(name = "consumer_key")
	public String getConsumerKey() {
		return super.getConsumerKey();
	}

	@Override
	@Column(name = "request_token")
	public String getRequestToken() {
		return super.getRequestToken();
	}

	@Override
	@Column(name = "token_secret")
	public String getTokenSecret() {
		return super.getTokenSecret();
	}

	@Override
	public String getVerifier() {
		return super.getVerifier();
	}

	@Override
	public String getSignature() {
		return super.getSignature();
	}

	@Override
	@Column(name = "access_token")
	public String getToken() {
		return super.getToken();
	}
}
