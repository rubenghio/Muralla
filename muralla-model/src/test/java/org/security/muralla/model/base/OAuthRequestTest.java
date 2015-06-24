package org.security.muralla.model.base;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.security.muralla.model.utils.OAuthUtils;

/**
 * Created by rghio on 6/24/15.
 */
public class OAuthRequestTest {
    private static final String URL_REQUEST_TOKEN = "http://localhost:8080/app-rest/rest/oauth/request_token";
    private static final String URL_REQUEST_TOKEN_METHOD = "POST";
    private OAuthRequest request;

    @Before
    public void before() {
        String value = "OAuth oauth_callback=oob, oauth_consumer_key=cli_portal, oauth_nonce=360722072, oauth_signature_method=HMAC-SHA1, oauth_timestamp=1434998640, oauth_version=1.0, oauth_signature=ZtCBm6X04dwrDKjPgXFdbLB0D3c%3D";
        try {
            request = new OAuthRequest(URL_REQUEST_TOKEN_METHOD, URL_REQUEST_TOKEN, value);
            Assert.assertNotNull("La solicitud NO debe ser nula!", request);
        } catch (Exception e) {
            Assert.fail("La creación de la solicitud NO debería arrojar excepción!");
        }
    }

    @Test
    public void testGetParamList() throws Exception {
        Assert.assertNotNull("La solicitud debe contener parámetros!", request.getParamList());
        Assert.assertTrue("La cantidad de elementos NO es la esperada", request.getParamList().size() == 7);
    }

    @Test
    public void testGetValue() throws Exception {
        Assert.assertEquals("cli_portal", request.getValue(OAuthUtils.OAUTH_CONSUMER_KEY));
        Assert.assertEquals("360722072", request.getValue(OAuthUtils.OAUTH_NONCE));
        Assert.assertEquals("HMAC-SHA1", request.getValue(OAuthUtils.OAUTH_SIGNATURE_METHOD));
    }

    @Test
    public void testGetBaseString() throws Exception {
        Assert.assertNotNull("La solicitud base NO debe ser nula!", request.getBaseString());
        Assert.assertEquals("POST&http%3A%2F%2Flocalhost%3A8080%2Fapp-rest%2Frest%2Foauth%2Frequest_token&oauth_callback%3Doob%26oauth_consumer_key%3Dcli_portal%26oauth_nonce%3D360722072%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1434998640%26oauth_version%3D1.0", request.getBaseString());
    }
}