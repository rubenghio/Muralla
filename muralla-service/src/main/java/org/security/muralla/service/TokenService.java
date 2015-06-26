package org.security.muralla.service;

import org.security.muralla.model.base.AccessTokenRegistry;
import org.security.muralla.model.base.AuthenticatedTokenRegistry;
import org.security.muralla.model.base.RequestTokenRegistry;

public interface TokenService {
	public void saveRequestToken(RequestTokenRegistry token);

	public void saveAccessToken(AccessTokenRegistry token);

	public void saveAuthenticatedToken(AuthenticatedTokenRegistry token);

	public RequestTokenRegistry getRequestToken(String token) throws Exception;

	public AuthenticatedTokenRegistry getAuthenticatedToken(String token)
			throws Exception;

	public AccessTokenRegistry getAccessToken(String token)
			throws Exception;
	
	public void checkDuplicateRequest(String timestamp, String nonce)
			throws Exception;
}
