package org.security.muralla.model.token;

import java.net.URLEncoder;
import java.util.UUID;

import org.apache.log4j.Logger;
import org.security.muralla.model.utils.OAuthUtils;

public class TokenProviderDefaultImpl implements TokenProvider {
	private static final Logger LOG = Logger
			.getLogger(TokenProviderDefaultImpl.class);

	@Override
	public String generateToken() throws Exception {
		LOG.info("Generating TOKEN default...");
		return URLEncoder.encode(
				UUID.randomUUID().toString().replaceAll("-", ""),
				OAuthUtils.ENCODING);
	}

	@Override
	public String generateTokenSecret() throws Exception {
		LOG.info("Generating TOKEN SECRET default...");
		return URLEncoder.encode(
				UUID.randomUUID().toString().replaceAll("-", ""),
				OAuthUtils.ENCODING);
	}

	@Override
	public void setTokenSeed(Object seed) {
		LOG.warn("TOKEN DEFAULT. Seed will not be used!!!");
	}

	@Override
	public void setTokenContent(Object content) {
		LOG.warn("TOKEN DEFAULT. Content will not be used!!!");
	}

}
