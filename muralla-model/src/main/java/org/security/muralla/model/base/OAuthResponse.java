package org.security.muralla.model.base;

import java.util.LinkedList;
import java.util.List;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import org.security.muralla.model.token.TokenProvider;
import org.security.muralla.model.token.TokenProviderDefaultImpl;
import org.security.muralla.model.utils.OAuthUtils;

public class OAuthResponse {
	private List<NameValuePair> parameters = new LinkedList<NameValuePair>();

	public OAuthResponse() throws Exception {
		this(new TokenProviderDefaultImpl());
	}

	public OAuthResponse(TokenProvider tokenProvider) throws Exception {
		parameters.add(new BasicNameValuePair(OAuthUtils.OAUTH_TOKEN,
				tokenProvider.generateToken()));
		parameters.add(new BasicNameValuePair(OAuthUtils.OAUTH_TOKEN_SECRET,
				tokenProvider.generateTokenSecret()));
	}

	public String getToken() {
		return parameters.get(0).getValue();
	}

	public String getTokenSecret() {
		return parameters.get(1).getValue();
	}

	public void addParameter(final String name, final String value) {
		parameters.add(new BasicNameValuePair(name, value));
	}

	@Override
	public String toString() {
		String rawResponse = URLEncodedUtils.format(parameters,
				OAuthUtils.ENCODING);
		return rawResponse;
	}
}
