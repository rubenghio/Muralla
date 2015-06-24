package org.security.muralla.model.utils;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class OAuthUtils {
    public static final String OAUTH_CALLBACK = "oauth_callback";
    public static final String OAUTH_CONSUMER_KEY = "oauth_consumer_key";
    public static final String OAUTH_NONCE = "oauth_nonce";
    public static final String OAUTH_SIGNATURE = "oauth_signature";
    public static final String OAUTH_SIGNATURE_METHOD = "oauth_signature_method";
    public static final String OAUTH_TIMESTAMP = "oauth_timestamp";
    public static final String OAUTH_VERSION = "oauth_version";
    public static final String OAUTH_TOKEN = "oauth_token";
    public static final String OAUTH_VERIFIER = "oauth_verifier";
    public static final String OAUTH_TOKEN_SECRET = "oauth_token_secret";
    public static final String OAUTH_CALLBACK_CONFIRMED = "oauth_callback_confirmed";
    public static final String MEMBER_ID = "member_id";
    public static final String ENCODING = "UTF-8";
    public static final String AMP = "&";
    public static final String EMPTY = "";
    public static final String DOUBLE_QUOTE = "\"";
    private static final String HMAC_SHA1 = "HmacSHA1";

    public static String getSignature(String baseString, String consumerSecret,
                                      String tokenSecret) throws UnsupportedEncodingException,
            NoSuchAlgorithmException, InvalidKeyException {
        String compoundSecret = consumerSecret + AMP + tokenSecret;
        byte[] keyBytes = compoundSecret.getBytes(ENCODING);
        SecretKey key = new SecretKeySpec(keyBytes, HMAC_SHA1);
        Mac mac = Mac.getInstance(HMAC_SHA1);
        mac.init(key);
        Base64 base64 = new Base64();
        return new String(base64.encode(mac.doFinal(baseString.toString()
                .getBytes(ENCODING))), ENCODING).trim();
    }
}
