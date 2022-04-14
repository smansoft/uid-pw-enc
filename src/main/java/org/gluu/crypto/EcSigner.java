/**
 * 
 */
package org.gluu.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author SMan
 * @version 2022-04-11
 */
public class EcSigner {
    
    @SuppressWarnings("unused")
    private static final Logger LOG = LoggerFactory.getLogger(EcSigner.class);

    public static final String DEF_EC_STD_NAME = "secp256r1";

    public static final String DEF_SIGN_ALG_NAME = "SHA256WITHECDSA";
    
    public static final String DEF_SIGN_KS_ALG_NAME = "SHA256WITHECDSA";    
    
    public static final String DEF_KEYSTORE_FORMAT = "PKCS12";
    
    private KeyStore keyStore;
    
    private ECGenParameterSpec eccGen;
    
    private String ksFPath;
    
    private String ksPassword;

    /**
     * 
     * @param ksFPath
     * @param ksPassword
     * @throws KeyStoreException 
     * @throws IOException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     */
    public EcSigner(final String ksFPath, final String ksPassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        this.ksFPath = ksFPath;
        this.ksPassword = ksPassword;        
        this.eccGen = new ECGenParameterSpec(DEF_EC_STD_NAME);
        this.keyStore = KeyStore.getInstance(DEF_KEYSTORE_FORMAT);
        File fKeyStore = new File(ksFPath);
        if (!fKeyStore.exists()) {
            this.keyStore.load(null, ksPassword.toCharArray());
            saveKs();
        }
        loadKs();
    }
    
    /**
     * 
     * @throws FileNotFoundException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public void loadKs() throws FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        keyStore.load(new FileInputStream(ksFPath), ksPassword.toCharArray());        
    }
    
    /**
     * 
     * @throws IOException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public void saveKs() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        keyStore.store(new FileOutputStream(this.ksFPath), this.ksPassword.toCharArray());
    }
    
    /**
     * 
     * @return
     * @throws NoSuchAlgorithmException 
     * @throws InvalidAlgorithmParameterException 
     */
    public KeyPair genECKeiPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = null;
        keyGen = KeyPairGenerator.getInstance("EC", EncryptTools.getProvider());
        keyGen.initialize(eccGen, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    /**
     * 
     * @param keyAlias
     * @param keyPair
     * @param owner
     * @param notBefore
     * @param notAfter
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws KeyStoreException
     * @throws OperatorCreationException
     */
    public void addECKeyPair(final String keyAlias, final KeyPair keyPair, final String owner,
            final Date notBefore, final Date notAfter)
                    throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, OperatorCreationException {

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        X500Name issuerName = new X500Name(owner);
        X500Name subjectName = new X500Name(owner);

        BigInteger serial = new BigInteger(256, new SecureRandom());

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, notBefore, notAfter, subjectName, publicKey);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);

        ASN1ObjectIdentifier extendedKeyUsage = new ASN1ObjectIdentifier("2.5.29.37").intern();
        builder.addExtension(extendedKeyUsage, false, new DERSequence(purposes));

        ContentSigner signer = new JcaContentSignerBuilder(DEF_SIGN_KS_ALG_NAME).setProvider(EncryptTools.getProvider()).build(privateKey);
        X509CertificateHolder holder = builder.build(signer);
        
        X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider(EncryptTools.getProvider()).getCertificate(holder);
        
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = x509Certificate;        
        
        this.keyStore.setKeyEntry(keyAlias, privateKey, ksPassword.toCharArray(), chain);
    }
    
    /**
     * 
     * @param keyAlias
     * @return
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     */
    public KeyPair getECKeyPair(final String keyAlias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        Key key = this.keyStore.getKey(keyAlias, ksPassword.toCharArray());
        PrivateKey privateKey = (PrivateKey) key;        
        Certificate certificate = this.keyStore.getCertificate(keyAlias);
        PublicKey publicKey = (PublicKey) certificate.getPublicKey();
        return new KeyPair(publicKey, privateKey); 
    }

    /**
     * 
     * @param keyAlias
     * @return
     * @throws KeyStoreException 
     */
    public boolean containsKeyAlias(final String keyAlias) throws KeyStoreException {
        return keyStore.containsAlias(keyAlias);
    }

    /**
     * 
     * @param keyAlias
     * @throws KeyStoreException 
     */
    public void deleteKeyAlias(final String keyAlias) throws KeyStoreException  {
        keyStore.deleteEntry(keyAlias);
    }
    
    /**
     * 
     * @param inData
     * @return
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws UnrecoverableKeyException 
     * @throws InvalidKeyException 
     * @throws SignatureException 
     */
    public String sign(final String keyAlias, final String inDataBase64) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        KeyPair keyPair = getECKeyPair(keyAlias);
        Signature signer = Signature.getInstance(DEF_SIGN_ALG_NAME, EncryptTools.getProvider());
        signer.initSign(keyPair.getPrivate());
        signer.update(Base64.getDecoder().decode(inDataBase64.getBytes()));
        byte[] signature = signer.sign();
        return new String(Base64.getEncoder().encode(signature));
    }

    /**
     * 
     * @param keyAlias
     * @param inDataBase64
     * @param idSingBase64
     * @return
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public boolean verify(final String keyAlias, final String inDataBase64, final String idSingBase64) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        KeyPair keyPair = getECKeyPair(keyAlias);
        Signature signer = Signature.getInstance(DEF_SIGN_ALG_NAME, EncryptTools.getProvider());
        signer.initVerify(keyPair.getPublic());   
        signer.update(Base64.getDecoder().decode(inDataBase64.getBytes()));
        return signer.verify(Base64.getDecoder().decode(idSingBase64.getBytes()));        
    }

    /**
     * 
     * @param ksFPath
     */
    public void setKsFPath(final String ksFPath) {
        this.ksFPath = ksFPath;
    }

    /**
     * 
     * @return
     */
    public String getKsFPath() {
        return this.ksFPath;
    }

    /**
     * 
     * @param ksPassword
     */
    public void setKsPassword(final String ksPassword) {
        this.ksPassword = ksPassword;
    }
    
    /**
     * 
     * @return
     */
    public String getKsPassword() {
        return this.ksPassword;
    }
    
    /**
     * 
     * @return
     */
    public KeyStore getKeyStore() {
        return this.keyStore;
    }
    
}

