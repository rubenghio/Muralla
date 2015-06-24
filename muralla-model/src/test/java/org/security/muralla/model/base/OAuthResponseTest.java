package org.security.muralla.model.base;

import org.junit.*;
import org.security.muralla.model.utils.OAuthUtils;

/**
 * Created by rghio on 6/24/15.
 */
public class OAuthResponseTest {
    private OAuthResponse response;

    @Before
    public void before() {
        try {
            response = new OAuthResponse();
        } catch (Exception e) {
            Assert.fail("La creación de la respuesta NO debería arrojar excepción!");
        }
    }

    @Test
    public void testGetToken() throws Exception {
        Assert.assertNotNull("La respuesta NO puede ser nula!", response);
        Assert.assertNotNull("El token NO puede ser nulo!", response.getToken());
    }

    @Test
    public void testGetTokenSecret() throws Exception {
        Assert.assertNotNull("La respuesta NO puede ser nula!", response);
        Assert.assertNotNull("La clave generada para la respuesta NO puede ser nula!", response.getTokenSecret());
    }

    @Test
    public void testToString() throws Exception {
        Assert.assertNotNull("La respuesta NO puede ser nula!", response);
        Assert.assertTrue("El token no contiene el parámetro 'oauth_token'!", response.toString().contains(OAuthUtils.OAUTH_TOKEN));
        Assert.assertTrue("El token no contiene el parámetro 'oauth_token_secret'!", response.toString().contains(OAuthUtils.OAUTH_TOKEN_SECRET));
    }

    @Test
    public void testAddParameter() throws Exception {
        Assert.assertNotNull("La respuesta NO puede ser nula!", response);
        response.addParameter("testParameter", "thisIsJustATest");
        Assert.assertTrue("El token no contiene el parámetro 'testParameter' o el valor es incorrecto!", response.toString().contains("testParameter=thisIsJustATest"));
    }

    @After
    public void after() {
        response = null;
    }
}