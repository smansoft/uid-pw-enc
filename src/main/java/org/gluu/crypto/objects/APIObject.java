/**
 * 
 */
package org.gluu.crypto.objects;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.gluu.crypto.primitives.AesEncrypter;
import org.gluu.crypto.primitives.EcSigner;
import org.gluu.crypto.tools.EncryptTools;
import org.gluu.crypto.tools.RandomStringGen;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author SMan
 * @version 2022-04-11
 */
public class APIObject extends ProcObject {

    /**
     * 
     * @author SMan
     *
     */
    public static class EncData {
        
        public String encSalt; 
        
        public String secretKey;
        
        public String iv;        
        
        public String srcData;
        
        public String encData;
        
        public String decrData;
        
        /**
         * 
         */
        public EncData() {
        }
        
        /**
         * 
         * @param encSalt
         * @param secretKey
         * @param iv
         * @param srcData
         * @param encData
         * @param decrData
         */
        public EncData (final String encSalt,
                final String secretKey,
                final String iv,
                final String srcData,
                final String encData,
                final String decrData) {
            this.encSalt = encSalt; 
            this.secretKey = secretKey;
            this.iv = iv;
            this.srcData = srcData;
            this.encData = encData;
            this.decrData = decrData;
        }
    }   
    
    private static final Logger LOG = LoggerFactory.getLogger(APIObject.class);    
    
    private static final String DEF_HASH_ALG = "SHA-256";
    
    private String encSalt;
    
    private String secretKeyStr;    

    /**
     * 
     * @param ecSigner
     * @param ksAlias
     * @param dnName
     */
    public APIObject(final EcSigner ecSigner, final String ksAlias, final String dnName) {
        super(ecSigner);
        
        setKsAlias(ksAlias);
        setDnName(dnName);
    }

    /**
     * 
     * @param signatureBase64
     * @throws NoSuchAlgorithmException
     */
    public void genKeys(final String signatureBase64) throws NoSuchAlgorithmException {
        
        this.encSalt = new RandomStringGen(AesEncrypter.DEF_AES_KEY_LENGTH, RandomStringGen.DEF_MODE_ALL).nextString();
       
        MessageDigest messageDigest = MessageDigest.getInstance(DEF_HASH_ALG, EncryptTools.getProvider());
        messageDigest.update(Base64.getDecoder().decode(signatureBase64.getBytes()));
        byte[] digestSign = messageDigest.digest();
        
        String digestSignStr = new String(Base64.getEncoder().encode(digestSign));
        
        char[] secretKey = new char[AesEncrypter.DEF_AES_KEY_LENGTH];
        System.arraycopy(new String(Base64.getDecoder().decode(digestSignStr.getBytes())).toCharArray(), 0, secretKey, 0, secretKey.length);
        this.secretKeyStr = new String(Base64.getEncoder().encode(new String(secretKey).getBytes()));

        LOG.info("secretKeyStr = {}", secretKeyStr);                
        LOG.info("encSalt = {}", encSalt);            
        
/*        
        byte[] iv = new byte[AesEncrypter.DEF_AES_KEY_LENGTH];
        random.nextBytes(iv);
        String ivStr = new String(Base64.getEncoder().encode(iv));
*/        

    }
    
}
