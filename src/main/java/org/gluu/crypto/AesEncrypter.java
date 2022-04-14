/**
 * 
 */
package org.gluu.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author SMan
 * @version 2022-04-11
 */
public class AesEncrypter {
    
    @SuppressWarnings("unused")
    private static final Logger LOG = LoggerFactory.getLogger(AesEncrypter.class);
    
    /**
     * 
     * @author SMan
     * @version 2022-04-11
     */
    public static class AesKeyData {
        public String key;
        public String iv;
        public String salt;        

        /**
         * 
         * @param key
         * @param iv
         * @param salt
         */
        public AesKeyData(final String key, final String iv, final String salt) {
            this.key = key;
            this.iv = iv;
            this.salt = salt;
        }
    }

    public static final String DEF_AES_MODE = "AES/GCM/NoPadding";
    
    public static final String DEF_KEY_FACTORY = "PBKDF2WithHmacSHA512";
    
    public static final int DEF_AES_KEY_LENGTH = 16;    // 128 bits only    
    
    public static final int DEF_ITER_COUNT = 1111;      
    
    private AesKeyData aesKeyData;
    
    private PBEKeySpec keySpec;
    
    private SecretKey curSecretKey;

    /**
     * 
     * @param aesKeyData
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeySpecException 
     */
    public AesEncrypter(final AesKeyData aesKeyData) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.aesKeyData = aesKeyData;
        keySpec = new PBEKeySpec(new String(Base64.getDecoder().decode(aesKeyData.key)).toCharArray(),
                Base64.getDecoder().decode(aesKeyData.key),
                DEF_ITER_COUNT, DEF_AES_KEY_LENGTH*8);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DEF_KEY_FACTORY, EncryptTools.getProvider());
        curSecretKey = keyFactory.generateSecret(keySpec);
    }

    /**
     * 
     * @param inDataBase64
     * @return
     * @throws NoSuchPaddingException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidAlgorithmParameterException 
     * @throws InvalidKeyException 
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     */
    public String encrData(final String inDataBase64) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(DEF_AES_MODE, EncryptTools.getProvider());
        cipher.init(Cipher.ENCRYPT_MODE, curSecretKey, new IvParameterSpec(Base64.getDecoder().decode(aesKeyData.iv)));
        byte [] encrData = cipher.doFinal(Base64.getDecoder().decode(inDataBase64));
        return new String(Base64.getEncoder().encode(encrData));
    }

    /**
     * 
     * @param inDataBase64
     * @return
     * @throws NoSuchPaddingException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidAlgorithmParameterException 
     * @throws InvalidKeyException 
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     */
    public String decrData(final String inDataBase64) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(DEF_AES_MODE, EncryptTools.getProvider());
        cipher.init(Cipher.DECRYPT_MODE, curSecretKey, new IvParameterSpec(Base64.getDecoder().decode(aesKeyData.iv)));
        byte [] decrData = cipher.doFinal(Base64.getDecoder().decode(inDataBase64));
        return new String(Base64.getEncoder().encode(decrData));
    }
}
