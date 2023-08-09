package com.example.myapplication;

public class Utils {
    private static final char[] DIGITS_LOWER =
            new char[] {
                    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
            };
    private static final char[] DIGITS_UPPER =
            new char[] {
                    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
            };

    private Utils() {}

    public static boolean bitBoolean(byte b, int pos) {
        return bit(b, pos) == 1;
    }

    public static int bit(byte b, int pos) {
        return b >> pos & 1;
    }

    public static String encodeHex(byte[] data) {
        return encodeHex(data, false);
    }

    public static byte[] decodeHex(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] =
                    (byte)
                            ((Character.digit(s.charAt(i), 16) << 4)
                                    + Character.digit(s.charAt(i + 1), 16));
        }

        return data;
    }

    public static String encodeHex(byte[] data, boolean toLowerCase) {
        return encodeHex(data, toLowerCase ? DIGITS_LOWER : DIGITS_UPPER);
    }

    private static String encodeHex(byte[] data, char[] toDigits) {
        int l = data.length;
        char[] out = new char[l << 1];
        int i = 0;

        for (int var5 = 0; i < l; ++i) {
            out[var5++] = toDigits[(240 & data[i]) >>> 4];
            out[var5++] = toDigits[15 & data[i]];
        }

        return new String(out);
    }

    public static byte setBit(byte res, int bitIndex, boolean value) {
        return value ? (byte) (res | 1 << bitIndex) : (byte) (res & ~(1 << bitIndex));
    }

}
