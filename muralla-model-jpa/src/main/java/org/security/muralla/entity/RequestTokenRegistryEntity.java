package org.security.muralla.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.security.muralla.model.base.RequestTokenRegistry;

@Entity
@Table(name = "oauth_request_token_registry")
public class RequestTokenRegistryEntity extends RequestTokenRegistry {

	public RequestTokenRegistryEntity() {
		super();
	}
	
	public RequestTokenRegistryEntity(RequestTokenRegistry model) {
		setNonce(model.getNonce());
		setTimestamp(model.getTimestamp());
		setCallback(model.getCallback());
		setSignature(model.getSignature());
		setVersion(model.getVersion());
		setSignatureMethod(model.getSignatureMethod());
		setConsumerKey(model.getConsumerKey());
		setToken(model.getToken());
		setTokenSecret(model.getTokenSecret());
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
	public String getCallback() {
		return super.getCallback();
	}

	@Override
	public String getSignature() {
		return super.getSignature();
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
	public String getToken() {
		return super.getToken();
	}

	@Override
	@Column(name = "token_secret")
	public String getTokenSecret() {
		return super.getTokenSecret();
	}
}
