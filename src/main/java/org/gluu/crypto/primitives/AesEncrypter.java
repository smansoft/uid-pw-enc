/**
 * 
 */
package org.gluu.crypto.primitives;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import org.gluu.crypto.exceptions.EncException;
import org.gluu.crypto.tools.EncryptTools;
import org.gluu.crypto.tools.RandomStringGen;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AesEncrypter, AES primitive, that provides Encrypting/Decrypting of String, using "AES/GCM/NoPadding" mode.
 * Length of Key: 128 bits.
 *
 * @author SMan
 * @version 2022-04-11
 */
public class AesEncrypter {
    
    @SuppressWarnings("unused")
    private static final Logger LOG = LoggerFactory.getLogger(AesEncrypter.class);
    
    /**
     * AesKeyData, key data: key and salt (in Base64) for AES.
     * 
     * @author SMan
     * @version 2022-04-11
     */
    public static class AesKeyData {

        public String keyBase64;
        public String saltBase64;

        /**
         * 
         */
        public AesKeyData() {
        }

        /**
         * 
         * @param keyBase64
         * @param saltBase64
         */
        public AesKeyData(final String keyBase64, final String saltBase64) {
            this.keyBase64 = keyBase64;
            this.saltBase64 = saltBase64;
        }
    }

    /**
     * Encrypting Data: source, encrypted, back decrypted.
     * Also contains init IV vector (for AES).  
     * 
     * @author SMan
     * @version 2022-04-11
     */
    public static class AesEncData {
        
        public String ivBase64;
        public String srcDataBase64;
        public String encDataBase64;
        public String decDataBase64;
        
        /**
         * 
         */
        public AesEncData() {
        }

        /**
         * 
         * @param ivBase64
         * @param srcDataBase64
         * @param encDataBase64
         * @param decDataBase64
         */
        public AesEncData(final String ivBase64, final String srcDataBase64, final String encDataBase64, final String decDataBase64) {
            this.ivBase64 = ivBase64;
            this.srcDataBase64 = srcDataBase64;
            this.encDataBase64 = encDataBase64;
            this.decDataBase64 = decDataBase64;
        }
    }

    public static final String DEF_AES_MODE = "AES/GCM/NoPadding";
    
    public static final String DEF_KEY_FACTORY = "PBKDF2WithHmacSHA512";
    
    public static final int DEF_AES_KEY_LENGTH = 16;    // 128 bits only    
    
    public static final int DEF_ITER_COUNT = 1111;      
    
    private AesKeyData aesKeyData;
    
    private SecretKey curSecretKey;

    /**
     * 
     * @param aesKeyData
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeySpecException 
     */
    public AesEncrypter(final AesKeyData aesKeyData) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.aesKeyData = aesKeyData;
        if(this.aesKeyData.saltBase64 == null) {
            this.aesKeyData.saltBase64 =
                    Base64.getEncoder().encodeToString(new RandomStringGen(AesEncrypter.DEF_AES_KEY_LENGTH, RandomStringGen.DEF_MODE_ALL).nextString().getBytes());
        }
/*        
        PBEKeySpec keySpec = new PBEKeySpec(new String(Base64.getDecoder().decode(aesKeyData.keyBase64)).toCharArray(),
                Base64.getDecoder().decode(aesKeyData.saltBase64),
                DEF_ITER_COUNT, DEF_AES_KEY_LENGTH*8);
*/
        char [] keyPassw = Arrays.copyOfRange(new String(Base64.getDecoder().decode(aesKeyData.keyBase64)).toCharArray(), 0, 16);
        byte [] salt = new byte[16];
        Arrays.fill(salt, (byte)0);        
        /// PBEKeySpec keySpec = new PBEKeySpec(keyPassw);
        PBEKeySpec keySpec = new PBEKeySpec(keyPassw, salt, DEF_ITER_COUNT, DEF_AES_KEY_LENGTH*8);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DEF_KEY_FACTORY, EncryptTools.getProvider());
        this.curSecretKey = keyFactory.generateSecret(keySpec);
    }

    /**
     * 
     * @param encData
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public void encData(final AesEncData encData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        if(encData.ivBase64 == null) {
            // encData.ivBase64 = Base64.getEncoder().encodeToString(new RandomStringGen(AesEncrypter.DEF_AES_KEY_LENGTH, RandomStringGen.DEF_MODE_ALL).nextString().getBytes());
            byte [] empty = new byte [16];
            Arrays.fill(empty, (byte)0);
            encData.ivBase64 = Base64.getEncoder().encodeToString(empty);
            
        }
        Cipher cipher = Cipher.getInstance(DEF_AES_MODE, EncryptTools.getProvider());
        cipher.init(Cipher.ENCRYPT_MODE, this.curSecretKey, new IvParameterSpec(Base64.getDecoder().decode(encData.ivBase64)));
        byte [] encDataArray = cipher.doFinal(Base64.getDecoder().decode(encData.srcDataBase64));
        encData.encDataBase64 = Base64.getEncoder().encodeToString(encDataArray);
    }

    /**
     * 
     * @param encData
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws EncException 
     */
    public void decData(final AesEncData encData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, EncException {
        if(encData.ivBase64 == null) {
            throw new EncException("ivBase64 (in AesEncData) is not defined");
        }
        Cipher cipher = Cipher.getInstance(DEF_AES_MODE, EncryptTools.getProvider());
        cipher.init(Cipher.DECRYPT_MODE, this.curSecretKey, new IvParameterSpec(Base64.getDecoder().decode(encData.ivBase64)));
        /// cipher.init(Cipher.DECRYPT_MODE, this.curSecretKey);
        byte [] decData = cipher.doFinal(Base64.getDecoder().decode(encData.encDataBase64));
        encData.decDataBase64 = Base64.getEncoder().encodeToString(decData);
    }
    
    /**
     * 
     * @return
     */
    public AesKeyData getAesKeyData() {
        return this.aesKeyData;
    }
}
