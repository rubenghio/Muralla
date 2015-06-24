package org.security.muralla.model.base;

import java.net.URLEncoder;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import org.security.muralla.model.utils.OAuthUtils;

public class
        OAuthResponse {
    private List<NameValuePair> parameters = new LinkedList<NameValuePair>();

    public OAuthResponse() throws Exception {
        String token = URLEncoder.encode(UUID.randomUUID().toString()
                .replaceAll("-", ""), OAuthUtils.ENCODING);
        String secret = URLEncoder.encode(UUID.randomUUID().toString()
                .replaceAll("-", ""), OAuthUtils.ENCODING);
        parameters.add(new BasicNameValuePair(OAuthUtils.OAUTH_TOKEN, token));
        parameters.add(new BasicNameValuePair(OAuthUtils.OAUTH_TOKEN_SECRET,
                secret));
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
