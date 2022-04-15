/**
 * 
 */
package org.gluu.crypto.tools;

import java.security.SecureRandom;
import java.util.Locale;

import org.bouncycastle.util.Arrays;

/**
 * RandomStringGen, random generator, tool class.
 * 
 * @author SMan
 * @version 2022-04-10
 */
public class RandomStringGen {

    public static final int DEF_MODE_ALPHA_LOWER = 0x01;

    public static final int DEF_MODE_ALPHA_UPPER = 0x02;

    public static final int DEF_MODE_DIGITS = 0x04;

    public static final int DEF_MODE_UNDERLINE = 0x08;

    public static final int DEF_MODE_SPEC_SYMBOLS = 0x10;

    public static final int DEF_MODE_ALL = DEF_MODE_ALPHA_LOWER | DEF_MODE_ALPHA_UPPER | DEF_MODE_DIGITS
            | DEF_MODE_UNDERLINE | DEF_MODE_SPEC_SYMBOLS;
    
    public static final int DEF_DEFAULT_LENGTH = 21;

    public static final String DEF_SYMBOLS_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static final String DEF_SYMBOLS_LOWER = DEF_SYMBOLS_UPPER.toLowerCase(Locale.ROOT);

    public static final String DEF_SYMBOLS_DIGITS = "0123456789";

    public static final String DEF_SYMBOLS_UNDERLINE = "_";

    public static final String DEF_SYMBOLS_SPEC = "-+*/\\|~@#$%^&<>()?=`'\"";

    private final SecureRandom secRandom = new SecureRandom();

    private final char[] symbols;

    private final int buffLength; 

    /**
     * Create an alphanumeric strings from given array of symbols.
     * 
     * @param length
     * @param symbols
     */
    public RandomStringGen(final int length,  String symbols) {
        if (length < 1 || symbols.length() < 2) {
            throw new IllegalArgumentException();
        }
        this.symbols = symbols.toCharArray();
        this.buffLength = length; 
    }

    /**
     * Create an alphanumeric strings from a secure generator.
     */
    public RandomStringGen(int length, int mode) {
        this(length, initSymbols(mode));
    }

    /**
     * Create session identifiers.
     */
    public RandomStringGen() {
        this(DEF_DEFAULT_LENGTH, DEF_MODE_ALL);
    }

    /**
     * Generate a random string.
     * 
     * @return
     */
    public String nextString() {
        final char[] buf = new char[this.buffLength];
        Arrays.fill(buf, (char) 0);
        for (int i = 0; i < buf.length; i++) {
            buf[i] = symbols[secRandom.nextInt(symbols.length)];
        }
        return new String(buf);
    }

    /**
     * Initializing the array of symbols. 
     * 
     * @param mode
     * @return
     */
    private static String initSymbols(final int mode) {
        StringBuffer strBuffer = new StringBuffer(); 
        if ((mode & DEF_MODE_ALPHA_LOWER) == DEF_MODE_ALPHA_LOWER) {
            strBuffer.append(DEF_SYMBOLS_LOWER);                
        }
        if ((mode & DEF_MODE_ALPHA_UPPER) == DEF_MODE_ALPHA_UPPER) {
            strBuffer.append(DEF_SYMBOLS_UPPER);
        }
        if ((mode & DEF_MODE_DIGITS) == DEF_MODE_DIGITS) {
            strBuffer.append(DEF_SYMBOLS_DIGITS);                
        }
        if ((mode & DEF_MODE_UNDERLINE) == DEF_MODE_UNDERLINE) {
            strBuffer.append(DEF_SYMBOLS_UNDERLINE);                
        }
        if ((mode & DEF_MODE_SPEC_SYMBOLS) == DEF_MODE_SPEC_SYMBOLS) {
            strBuffer.append(DEF_SYMBOLS_SPEC);                
        }
        return strBuffer.toString(); 
    }

}
