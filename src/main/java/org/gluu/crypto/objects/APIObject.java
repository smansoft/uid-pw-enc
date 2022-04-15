/**
 * 
 */
package org.gluu.crypto.objects;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.gluu.crypto.exceptions.EncException;
import org.gluu.crypto.primitives.AesEncrypter;
import org.gluu.crypto.primitives.EcSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * API Object.
 * 
 * @author SMan
 * @version 2022-04-11
 */
public class APIObject extends ProcObject {
    
    @SuppressWarnings("unused")
    private static final Logger LOG = LoggerFactory.getLogger(APIObject.class);
    
    private AesEncrypter aesEncrypter;    

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
     * @param procData
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public void initAes(final ProcData procData) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.aesEncrypter = new AesEncrypter(new AesEncrypter.AesKeyData(procData.webSiteSignatureBase64, null));
        procData.secretKeyBase64 = this.aesEncrypter.getAesKeyData().keyBase64;
        procData.encSaltBase64 = this.aesEncrypter.getAesKeyData().saltBase64;
    }

    /**
     * 
     * @param procData
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public void encrypt(final ProcData procData) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        
        AesEncrypter.AesEncData aesEncData = new AesEncrypter.AesEncData();
        
        aesEncData.ivBase64 = procData.ivBase64;
        aesEncData.srcDataBase64 = procData.srcDataBase64;
        
        this.aesEncrypter.encData(aesEncData);
        
        procData.ivBase64 = aesEncData.ivBase64;
        procData.srcDataBase64 = aesEncData.srcDataBase64;
        procData.encDataBase64 = aesEncData.encDataBase64;
    }

    /**
     * 
     * @param procData
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws EncException
     */
    public void decrypt(final ProcData procData) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, EncException {
        
        AesEncrypter.AesEncData aesEncData = new AesEncrypter.AesEncData();        
        
        aesEncData.ivBase64 = procData.ivBase64;
        aesEncData.srcDataBase64 = procData.srcDataBase64;
        aesEncData.encDataBase64 = procData.encDataBase64;
        
        this.aesEncrypter.decData(aesEncData);
        
        procData.ivBase64 = aesEncData.ivBase64;
        procData.srcDataBase64 = aesEncData.srcDataBase64;
        procData.encDataBase64 = aesEncData.encDataBase64;
        procData.decDataBase64 = aesEncData.decDataBase64;
    }
    
    /**
     * 
     * @param procData
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws UnrecoverableKeyException 
     */
    public void initEcSignatureKeys(final ProcData procData) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        procData.apiEcPrivateKeyBase64 = Base64.getEncoder().encodeToString(getEcSigner().getECKeyPair(getKsAlias()).getPrivate().getEncoded());                
        procData.apiEcPublicKeyBase64 = Base64.getEncoder().encodeToString(getEcSigner().getECKeyPair(getKsAlias()).getPublic().getEncoded());
    }

}
