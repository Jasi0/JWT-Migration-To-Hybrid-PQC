package com.example.common;

import java.util.Base64;

//URL-safe Base64 utility without padding, as used by JWS Compact Serialization
public final class Base64Url {

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    private Base64Url() {
        // utility
    }

    public static String encode(byte[] bytes) {
        return URL_ENCODER.encodeToString(bytes);
    }

    public static byte[] decode(String s) {
        return URL_DECODER.decode(s);
    }
}