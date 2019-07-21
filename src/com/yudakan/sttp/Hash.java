package com.yudakan.sttp;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * -- STTP --
 * Sequential Two Times Pad
 * Hash Class
 *
 * @author yka
 * @version 1.0
 */
public class Hash {

    /* Attributes */
    private static MessageDigest md;
    private static int len;

    static {
        try {
            md = MessageDigest.getInstance("SHA-256");
            len = 32;
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e.getMessage());
        }
    }


    /* Constructors */
    private Hash() {}


    /* Getters */
    public static int length() {
        return len;
    }


    /* Methods */
    public static byte[] create(byte[] src) {
        return md.digest(src);
    }
}