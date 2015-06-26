package org.security.muralla.model.token;

public interface TokenProvider {
	public String generateToken() throws Exception;

	public String generateTokenSecret() throws Exception;

	public void setTokenSeed(Object seed);

	public void setTokenContent(Object content);
}
