package org.gluu.crypto;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.gluu.crypto.exceptions.EncException;
import org.gluu.crypto.objects.APIObject;
import org.gluu.crypto.objects.ProcObject;
import org.gluu.crypto.objects.WebSiteObject;
import org.gluu.crypto.primitives.EcSigner;
import org.gluu.crypto.tools.PrintTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

/**
 * Main Class, that provides modeling of Crypto Processing, using objects: WebSite, API.         
 * 
 * @author SMan
 * @version 2022-04-11
 */
public class EncryptingUidPw 
{
    private static final Logger LOG = LoggerFactory.getLogger(EncryptingUidPw.class);
    
    static {
        try {
            Security.addProvider(new BouncyCastleProvider());    
        }
        catch (Exception e) {
            LOG.error(PrintTools.stackTraceToString(e), e);
        }
    }
    
    // WebSite
    private static final String DEF_WEP_SITE_KS_FPATH = "./web-site.pkcs12";

    private static final String DEF_WEB_SITE_KS_ALIAS = "web-site-alias";
    
    private static final String DEF_WEB_SITE_DN_NAME = "CN=WebSite Certificate";
    
    // API
    private static final String DEF_API_KS_FPATH = "./api.pkcs12";
    
    private static final String DEF_API_KS_ALIAS = "api-alias";
    
    private static final String DEF_API_DN_NAME = "CN=API Certificate";

    // Common
    private static final String DEF_KS_PASSWORD = "secret";    
    
    /**
     * Entry Point.
     *  
     * @param args
     */
    public static void main( String[] args )
    {
        try {
            LOG.info("Application uid-pw-enc started...");
            ProcObject.ProcData procData = new ProcObject.ProcData();
            LOG.info("------------------------");            
            LOG.info("> Creating WebSite Object:");            
            WebSiteObject webSite = new WebSiteObject(new EcSigner(DEF_WEP_SITE_KS_FPATH, DEF_KS_PASSWORD), DEF_WEB_SITE_KS_ALIAS, DEF_WEB_SITE_DN_NAME);
            LOG.info("< WebSite Object has been created...");
            
            LOG.info("> Creating API Object:");            
            APIObject api = new APIObject(new EcSigner(DEF_API_KS_FPATH, DEF_KS_PASSWORD), DEF_API_KS_ALIAS, DEF_API_DN_NAME);
            LOG.info("< API Object has been created...");            
            
            LOG.info("------------------------");            
            LOG.info("> Generating Uid and Password:");
            webSite.genUidAndPassw(procData);
            LOG.info("Uid (Base64): {}", procData.uidBase64);
            LOG.info("Password (Base64): {}", procData.passwordBase64);            
            LOG.info("< Uid and Password have been generated...");
            LOG.info("------------------------");            
            LOG.info("> WebSite Object: Generating EC signature keys:");            
            webSite.genSignKeys();
            webSite.initEcSignatureKeys(procData);
            LOG.info("WebSite Ec Private Key (Base64) = {}", procData.webSiteEcPrivateKeyBase64);
            LOG.info("WebSite Ec Public Key (Base64) = {}", procData.webSiteEcPublicKeyBase64);            
            LOG.info("< WebSite Object: EC signature keys have been generated...");
            LOG.info("------------------------");
            LOG.info("> WebSite Object: Signing Uid:");            
            procData.webSiteSignatureBase64 = webSite.signData(procData.uidBase64);
            LOG.info("WebSite Object Signature (Base64) = {}", procData.webSiteSignatureBase64);
            LOG.info("< WebSite Object: Uid has been signed...");
            LOG.info("------------------------");
            LOG.info("> WebSite Object: Verifying signature of Uid:");            
            boolean verify = webSite.verifyData(procData.uidBase64, procData.webSiteSignatureBase64);
            LOG.info("WebSite Object Verifying = {}", verify);
            LOG.info("< WebSite Object: Signature of Uid has been verified...");
            LOG.info("------------------------");
            LOG.info("> API Object: Generating EC signature keys:");            
            api.genSignKeys();
            api.initEcSignatureKeys(procData);
            LOG.info("API Ec Private Key (Base64) = {}", procData.apiEcPrivateKeyBase64);
            LOG.info("API Ec Public Key (Base64) = {}", procData.apiEcPublicKeyBase64);            
            procData.apiSignatureBase64 = api.signData(procData.webSiteSignatureBase64);
            LOG.info("API Object Signature (Base64) = {}", procData.apiSignatureBase64);            
            LOG.info("< API Object: EC signature keys have been generated...");
            LOG.info("------------------------");
            LOG.info("> API Object: Verifying signature of WebSite Object signature:");
            verify = api.verifyData(procData.webSiteSignatureBase64, procData.apiSignatureBase64);
            LOG.info("API Object Verifying = {}", verify);
            LOG.info("< API Object: Signature of WebSite Object signature has been verified...");
            LOG.info("------------------------");
            LOG.info("> API Object: Initializing AES key, salt:");
            api.initAes(procData);
            LOG.info("< API Object: AES key, salt have been initialized...");            
            LOG.info("------------------------");
            procData.srcDataBase64 = procData.passwordBase64;
            LOG.info("> API Object: Encrypting password:");            
            api.encrypt(procData);
            LOG.info("< API Object: Password has been encrypted...");            
            LOG.info("------------------------");
            LOG.info("> API Object: Back decrypting password:");            
            api.decrypt(procData);
            LOG.info("< API Object: Password has been decrypted...");
            LOG.info("------------------------");
            LOG.info("AES Encrypting Data:");            
            LOG.info("src data (Base64) = {}", procData.srcDataBase64);                
            LOG.info("enc data (Base64) = {}", procData.encDataBase64);                
            LOG.info("dec data (Base64) = {}", procData.decDataBase64);
            LOG.info("------------------------");
            LOG.info("password (Decoded) = {}", new String(Base64.getDecoder().decode(procData.passwordBase64.getBytes())));
            LOG.info("src data (Decoded) = {}", new String(Base64.getDecoder().decode(procData.srcDataBase64.getBytes())));
            LOG.info("dec data (Decoded) = {}", new String(Base64.getDecoder().decode(procData.decDataBase64.getBytes())));
            LOG.info("------------------------");
            String xmlProcData = procData.toXML();
            LOG.info("Flow Data in XML format:");            
            LOG.info("xmlProcData = {}", xmlProcData);
            LOG.info("------------------------");
            LOG.info("Application uid-pw-enc finished...");            
        }
        catch (NoSuchAlgorithmException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (InvalidAlgorithmParameterException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (TransformerFactoryConfigurationError e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (IOException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (KeyStoreException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (CertificateException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (OperatorCreationException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (UnrecoverableKeyException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);
        } catch (InvalidKeyException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);
        } catch (SignatureException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (InvalidKeySpecException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (NoSuchPaddingException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (IllegalBlockSizeException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (BadPaddingException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (EncException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (ParserConfigurationException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);
        } catch (TransformerException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        }
    }
}
