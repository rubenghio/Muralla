package org.security.muralla.entity;

import java.util.List;

import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.Table;

import org.security.muralla.model.base.AccessTokenRegistry;

@Entity
@Table(name = "oauth_access")
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
		setRoles(model.getRoles());
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
	
	@ElementCollection(fetch = FetchType.EAGER)
	@CollectionTable(name = "oauth_access_rol", joinColumns = @JoinColumn(name = "id"))
	@Column(name = "rol")
	public List<String> getRoles() {
		return super.getRoles();
	}
}
