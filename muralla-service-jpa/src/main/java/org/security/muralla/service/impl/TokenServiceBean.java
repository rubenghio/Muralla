package org.security.muralla.service.impl;

import java.util.List;

import javax.annotation.security.PermitAll;
import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.security.muralla.entity.AccessTokenRegistryEntity;
import org.security.muralla.entity.AuthenticatedTokenRegistryEntity;
import org.security.muralla.entity.RequestTokenRegistryEntity;
import org.security.muralla.model.base.AccessTokenRegistry;
import org.security.muralla.model.base.AuthenticatedTokenRegistry;
import org.security.muralla.model.base.OAuthResponse;
import org.security.muralla.model.base.RequestTokenRegistry;
import org.security.muralla.model.token.TokenProvider;
import org.security.muralla.service.TokenService;

@Stateless
@PermitAll
public class TokenServiceBean implements TokenService {
	@PersistenceContext(unitName = "muralla-security-oauth")
	private EntityManager em;
	@Inject
	private TokenProvider tokenProviderDefault;

	private void save(Object token) {
		em.persist(token);
	}

	@Override
	public RequestTokenRegistry getRequestToken(String token) throws Exception {
		return (RequestTokenRegistry) getToken(token,
				RequestTokenRegistryEntity.class.getName());
	}

	@Override
	public AuthenticatedTokenRegistry getAuthenticatedToken(String token)
			throws Exception {
		return (AuthenticatedTokenRegistry) getToken(token,
				AuthenticatedTokenRegistryEntity.class.getName());
	}

	@SuppressWarnings("unchecked")
	private Object getToken(String token, String className) throws Exception {
		Query query = em.createQuery("from " + className
				+ " where token = :token");
		query.setParameter("token", token);
		List<Object> list = query.getResultList();
		if (list == null || list.isEmpty()) {
			throw new Exception("Authenticated token was not found!!!");
		}
		return list.get(0);
	}

	@Override
	@SuppressWarnings("unchecked")
	public void checkDuplicateRequest(String timestamp, String nonce)
			throws Exception {
		Query query = em
				.createQuery("from RequestTokenRegistryEntity where timestamp = :timestamp and nonce = :nonce");
		query.setParameter("timestamp", timestamp);
		query.setParameter("nonce", nonce);
		List<RequestTokenRegistry> list = query.getResultList();
		if (list != null && !list.isEmpty()) {
			throw new Exception(
					"Invalid request. Token was already requested!!!");
		}
	}

	@Override
	public void saveRequestToken(RequestTokenRegistry token) {
		save(new RequestTokenRegistryEntity(token));
	}

	@Override
	public void saveAccessToken(AccessTokenRegistry token) {
		save(new AccessTokenRegistryEntity(token));
	}

	@Override
	public void saveAuthenticatedToken(AuthenticatedTokenRegistry token) {
		save(new AuthenticatedTokenRegistryEntity(token));
	}

	@Override
	public AccessTokenRegistry getAccessToken(String token) throws Exception {
		return (AccessTokenRegistry) getToken(token,
				AccessTokenRegistryEntity.class.getName());
	}

	@Override
	public OAuthResponse createRequestTokenResponse(Object content, Object seed)
			throws Exception {
		return new OAuthResponse(tokenProviderDefault);
	}

	@Override
	public OAuthResponse createAccessTokenResponse(Object content, Object seed)
			throws Exception {
		return new OAuthResponse(tokenProviderDefault);
	}
}
