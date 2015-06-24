package org.security.muralla.model.utils;

import java.net.URLDecoder;

import org.junit.Assert;
import org.junit.Test;
import org.security.muralla.model.base.OAuthRequest;

/**
 * Created by rghio on 6/24/15.
 */
public class OAuthUtilsTest {
	private static final String URL_REQUEST_TOKEN = "http://localhost:8080/col-prestamo-rest/service/oauth/request_token";
    private static final String URL_REQUEST_TOKEN_METHOD = "POST";
    private static final String SECRET = "secret";
    private static final String EMPTY = "";

    @Test
    public void testGetSignature() throws Exception {
        String value = "OAuth oauth_callback=oob, oauth_consumer_key=cli_portal, oauth_nonce=360722072, oauth_signature_method=HMAC-SHA1, oauth_timestamp=1434998640, oauth_version=1.0, oauth_signature=ZtCBm6X04dwrDKjPgXFdbLB0D3c%3D";
        try {
            OAuthRequest request = new OAuthRequest(URL_REQUEST_TOKEN_METHOD, URL_REQUEST_TOKEN, value);
            String signature = OAuthUtils.getSignature(request.getBaseString(), SECRET, EMPTY);
            String decoded = URLDecoder.decode(
                    request.getValue(OAuthUtils.OAUTH_SIGNATURE),
                    OAuthUtils.ENCODING);
            Assert.assertEquals(signature, decoded);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }
}