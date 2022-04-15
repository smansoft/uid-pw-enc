/**
 * 
 */
package org.gluu.crypto.objects;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.operator.OperatorCreationException;
import org.gluu.crypto.primitives.EcSigner;

/**
 * @author SMan
 *
 */
public abstract class ProcObject {
    
    private static int DEF_CERTIFICATE_PERIOD = 1; // years 
    
    private String uid;
    private String password;
    
    private EcSigner ecSigner;
    
    private String ksAlias;
    private String dnName;    

    /**
     * 
     * @param ecSigner
     */
    protected ProcObject(final EcSigner ecSigner) {
        this.ecSigner = ecSigner;
    }
    
    /**
     * 
     * @param uid
     */
    public void setUid(final String uid) {
        this.uid = uid; 
    }

    /**
     * 
     * @return
     */
    public String getUid() {
        return this.uid; 
    }
    
    /**
     * 
     * @param password
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * 
     * @return
     */
    public String getPassword() {
        return this.password;
    }
    
    /**
     * 
     * @param ecSigner
     */
    public void setEcSigner(final EcSigner ecSigner) {
        this.ecSigner = ecSigner;
    }

    /**
     * 
     * @return
     */
    public EcSigner getEcSigner() {
        return this.ecSigner;
    }
    
    /**
     * 
     * @param ksAlias
     */
    public void setKsAlias(final String ksAlias) {
        this.ksAlias = ksAlias;
    }

    /**
     * 
     * @return
     */
    public String getKsAlias() {
        return this.ksAlias;
    }

    
    /**
     * 
     * @param dnName
     */
    public void setDnName(final String dnName) {
        this.dnName = dnName;
    }

    /**
     * 
     * @return
     */
    public String getDnName() {
        return this.dnName;
    }
    
    /**
     * 
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws CertificateException
     * @throws KeyStoreException
     * @throws OperatorCreationException
     * @throws IOException
     */
    public void genSignKeys() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, CertificateException, KeyStoreException, OperatorCreationException, IOException {
        File ksFile = new File(this.ecSigner.getKsFPath());
        if(ksFile.exists()) {
            ksFile.delete();
        }
        KeyPair keyPair = this.ecSigner.genECKeiPair();
        
        Calendar calendar = Calendar.getInstance();
        Date currDate = calendar.getTime();
        calendar.add(Calendar.YEAR, DEF_CERTIFICATE_PERIOD);
        Date nextYear = calendar.getTime();
        
        this.ecSigner.addECKeyPair(this.ksAlias, keyPair, this.dnName, currDate, nextYear);
        this.ecSigner.saveKs();
        this.ecSigner.loadKs();

        if(!this.ecSigner.containsKeyAlias(this.ksAlias)) {
            throw new KeyStoreException(String.format("Alias %s not found", this.ksAlias));
        }
    }

    /**
     * 
     * @return
     * @throws UnrecoverableKeyException
     * @throws InvalidKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     */
    public String signId() throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, SignatureException {
        return signData(this.uid);
    }

    /**
     * 
     * @param idSingBase64
     * @return
     * @throws UnrecoverableKeyException
     * @throws InvalidKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     */
    public boolean verifySignId(final String idSingBase64) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, SignatureException {
        return verifyData(this.uid, idSingBase64);
    }
    
    /**
     * 
     * @param inDataBase64
     * @return
     * @throws UnrecoverableKeyException
     * @throws InvalidKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     */
    public String signData(final String inDataBase64) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, SignatureException {
        return this.ecSigner.sign(this.ksAlias, inDataBase64);        
    }

    /**
     * 
     * @param inDataBase64
     * @param idSingBase64
     * @return
     * @throws UnrecoverableKeyException
     * @throws InvalidKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     */
    public boolean verifyData(final String inDataBase64, final String idSingBase64) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, SignatureException {
        return this.ecSigner.verify(this.ksAlias, inDataBase64, idSingBase64);        
    }
}
