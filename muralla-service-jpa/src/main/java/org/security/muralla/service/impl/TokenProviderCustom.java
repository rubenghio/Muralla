package org.security.muralla.service.impl;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.codehaus.jackson.map.ObjectMapper;
import org.security.muralla.model.token.TokenProvider;
import org.security.muralla.model.utils.OAuthUtils;

public class TokenProviderCustom implements TokenProvider {
	private static final Logger LOG = Logger
			.getLogger(TokenProviderCustom.class);
	private Object content;

	@Override
	public String generateToken() throws Exception {
		LOG.info("Generating TOKEN...");
		String username = content.toString();
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("username", username);
		map.put("timestamp", System.currentTimeMillis());
		List<String> roles = new ArrayList<String>();
		roles.add("manager");
		roles.add("prueba");
		map.put("roles", roles);
		ObjectMapper mapper = new ObjectMapper();
		Base64 base64 = new Base64();
		byte[] encodedToken = base64.encode(mapper.writeValueAsString(map)
				.getBytes());
		return new String(encodedToken, OAuthUtils.ENCODING);
	}

	@Override
	public String generateTokenSecret() throws Exception {
		LOG.info("Generating TOKEN SECRET...");
		return URLEncoder.encode(
				UUID.randomUUID().toString().replaceAll("-", ""),
				OAuthUtils.ENCODING);
	}

	@Override
	public void setTokenSeed(Object seed) {
		LOG.info("Setting 'seed' to generate token secret...");
	}

	@Override
	public void setTokenContent(Object content) {
		LOG.info("Setting 'content' to generate token...");
		this.content = content;
	}
}