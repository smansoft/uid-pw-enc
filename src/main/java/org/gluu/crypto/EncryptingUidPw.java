package org.gluu.crypto;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.util.Base64;
import java.util.Date;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

/**
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
     * 
     * @param args
     */
    public static void main( String[] args )
    {
        try {
            LOG.info("Application uid-pw-enc started...");

/*            
            Security.addProvider(new BouncyCastleProvider());        
            Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
*/
/*
            LOG.trace("Application initialized - TRACE");
            LOG.trace("Application initialized - TRACE");
            LOG.debug("Application initialized - DEBUG");
            LOG.info("Application initialized - INFO");
            LOG.warn("Application initialized - WARN");
            LOG.error("Application initialized - ERROR");
            
            Object obj = new Object();
            
            synchronized(obj) {
                
                LOG.info("Application initialized - INFO");
                
                obj.wait(100);
                
                LOG.info("Application initialized - INFO");
                
                obj.wait(131);
                
                LOG.info("Application initialized - INFO");
                
                obj.wait(300);
                
                LOG.info("Application initialized - INFO");        
                
            }
*/
            
            RandomStringGen randomStringAll = new RandomStringGen(16, RandomStringGen.DEF_MODE_ALL);
            
            LOG.info("------------------------------------------- >>");        
            for (int i = 0; i < 10; i++) {
                String rndString = randomStringAll.nextString();
                LOG.info("i = {}; rndString = {}", i, rndString);            
            }
            LOG.info("------------------------------------------- <<");
            
            RandomStringGen randomStringAlpa = new RandomStringGen(16, RandomStringGen.DEF_MODE_ALPHA_LOWER);
            
            LOG.info("------------------------------------------- >>");        
            for (int i = 0; i < 10; i++) {
                String rndString = randomStringAlpa.nextString();
                LOG.info("i = {}; rndString = {}", i,    rndString);            
            }
            LOG.info("------------------------------------------- <<");
            
//            Encoder base64Encoder = Base64.getEncoder();
//            Decoder base64Decoder = Base64.getDecoder();
            
            String uid = new RandomStringGen(8, RandomStringGen.DEF_MODE_DIGITS).nextString();
            String password = new RandomStringGen(21, RandomStringGen.DEF_MODE_ALL).nextString();

            LOG.info("uid = {}", uid);
            LOG.info("password = {}", password);
            
            {
                WebSite webSite = new WebSite(new EcSigner(DEF_WEP_SITE_KS_FPATH, DEF_KS_PASSWORD),
                        DEF_WEB_SITE_KS_ALIAS, DEF_WEB_SITE_DN_NAME);
                webSite.genUidAndPassw();
                webSite.genSignKeys();

                String signIdWebSite = webSite.signId();
                LOG.info("signIdWebSite = {}", signIdWebSite);

                boolean verify = webSite.verifySignId(signIdWebSite);
                LOG.info("verify = {}", verify);                
                
                API api = new API(new EcSigner(DEF_API_KS_FPATH, DEF_KS_PASSWORD),
                        DEF_API_KS_ALIAS, DEF_API_DN_NAME);
                api.genSignKeys();
                
/*                
                private static final String DEF_WEP_SITE_FPATH = "./web-site.pkcs12";    
                
                private static final String DEF_API_FPATH = "./api.pkcs12";
                
                private static final String DEF_PASSWORD = "secret"; 
*/

/*                
                1. ks file;
                2. ks password;
                3. alias;
                4. dnName;
                
                1. gens uid/passw;                
                
                2. WebSite setup uid/passw
*/  
                
/*                
                3. WebSite.proc() {
                    1. WebSite gens uid/passw;                
                    2. Gen Keys;
                    3. signs uid;
                }
*/
/*                
                4. WebSite sets uid/passw and signature of uid in API;
                
                API.proc()
                
                5. API signs signature
                
                6. API generates
*/                   
            }
            
            
            {
                
                new File("./uid-pw-enc.pkcs12").delete();                
                
                EcSigner ecSigner = new EcSigner("./uid-pw-enc.pkcs12", "secret");
                KeyPair keyPairWS = ecSigner.genECKeiPair();
                
                Calendar calendar = Calendar.getInstance();
                
                Date currDate = calendar.getTime();
                calendar.add(Calendar.YEAR, 1);
                Date nextYear = calendar.getTime();
                
                ecSigner.addECKeyPair("web_site_keys", keyPairWS, "CN=WebSite", currDate, nextYear);

                ecSigner.saveKs();
                ecSigner.loadKs();

                boolean isWebSiteKeys = ecSigner.containsKeyAlias("web_site_keys");
                
                LOG.info("isWebSiteKeys = {}", isWebSiteKeys);
                
                KeyPair keyPair = ecSigner.getECKeyPair("web_site_keys");
                
                LOG.info("keyPair.getPrivate().getAlgorithm() = {}", keyPair.getPrivate().getAlgorithm());
                LOG.info("keyPair.getPublic().getAlgorithm() = {}", keyPair.getPublic().getAlgorithm());
                
                String signature = ecSigner.sign("web_site_keys", new String(Base64.getEncoder().encode(uid.getBytes())));
                
                LOG.info("signature = {}", signature);

                boolean verify = ecSigner.verify("web_site_keys", new String(Base64.getEncoder().encode(uid.getBytes())), signature);
                
                LOG.info("verify = {}", verify);

                SecureRandom random = new SecureRandom();
                
                byte[] iv = new byte[AesEncrypter.DEF_AES_KEY_LENGTH];
                random.nextBytes(iv);
                String ivStr = new String(Base64.getEncoder().encode(iv));
                
                byte [] digestSign = null;
                String digestSignStr;
                
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256", "BC");
                messageDigest.update(Base64.getDecoder().decode(signature.getBytes()));
                digestSign = messageDigest.digest();
                
                digestSignStr = new String(Base64.getEncoder().encode(digestSign));
                
                char[] secretKey = new char[AesEncrypter.DEF_AES_KEY_LENGTH];
                System.arraycopy(new String(Base64.getDecoder().decode(digestSignStr.getBytes())).toCharArray(), 0, secretKey, 0, secretKey.length);
                String secretKeyStr = new String(Base64.getEncoder().encode(new String(secretKey).getBytes())); 
                
                String encSalt = new RandomStringGen(AesEncrypter.DEF_AES_KEY_LENGTH, RandomStringGen.DEF_MODE_ALL).nextString();
                
                LOG.info("secretKeyStr = {}", secretKeyStr);                
                LOG.info("ivStr = {}", ivStr);                
                LOG.info("encSalt = {}", encSalt);                
                
                AesEncrypter aesEncrypter = new AesEncrypter( new AesEncrypter.AesKeyData(secretKeyStr, ivStr, encSalt));
                
                String passwEncrypted = aesEncrypter.encrData(new String(Base64.getEncoder().encode(password.getBytes())));
                
                LOG.info("passwEncrypted = {}", passwEncrypted);
                
                String passwDecrypted = aesEncrypter.decrData(passwEncrypted);
                
                LOG.info("passwDecrypted = {}", passwDecrypted);
                
                LOG.info("passwDecrypted = {}", new String(Base64.getDecoder().decode(passwDecrypted)));                
                
            }
/*            
            {
                KeyPairGenerator keyGen = null;
                
                ECGenParameterSpec eccGen = new ECGenParameterSpec("secp256r1");            
                
                keyGen = KeyPairGenerator.getInstance("EC", provider);
                keyGen.initialize(eccGen, new SecureRandom());
                
                // Generate the key
                KeyPair keyPair = keyGen.generateKeyPair();
                PrivateKey privateKey = keyPair.getPrivate();
                PublicKey publicKey = keyPair.getPublic();
                
                Signature signer = Signature.getInstance("SHA256WITHECDSA", provider);
                signer.initSign(privateKey);
                
                signer.update(uid.getBytes());
                byte[] sign = signer.sign();
                
                signBase64_1 = new String(base64Encoder.encode(sign));
                
                LOG.info("signBase64 = {}", signBase64_1);
                LOG.info("signBase64.length() = {}", signBase64_1.length());            

                byte[] signDec = base64Decoder.decode(signBase64_1.getBytes());

                Signature signerVerify = Signature.getInstance("SHA256WITHECDSA", provider);
                signerVerify.initVerify(publicKey);         
                
                signerVerify.update(uid.getBytes());
                boolean verifyRes = signerVerify.verify(signDec);

                LOG.info("verifyRes = {}", verifyRes);
            }
            
            String xmlStr1 = null;
            String xmlStr2 = null;
            String xmlStr3 = null;
            String xmlStr4 = null;
            String xmlStr5 = null;
            String xmlStr6 = null;
            
            {
                DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
                Document document = documentBuilder.newDocument();

                Element uid_passw_element = document.createElement("uid_passw");
                
                document.appendChild(uid_passw_element);            
                
                Element uid_element =  document.createElement("uid");
                Element passw_element =  document.createElement("passw");
                
                uid_passw_element.appendChild(uid_element);
                uid_passw_element.appendChild(passw_element);
                
                // Element signature_ws_element =  document.createElement("signature_ws");
                
                uid_element.setTextContent(new String(base64Encoder.encode(uid.getBytes())));
                passw_element.setTextContent(new String(base64Encoder.encode(password.getBytes())));
                
                String docTextContext = document.getTextContent();
                
                LOG.info("uid_element.getTextContent() = {}", uid_element.getTextContent());
                LOG.info("uid_element.toString() = {}", uid_element.toString());
                
                LOG.info("docTextContext = {}", docTextContext);     

                LOG.info("xml_document = {}", document.toString());
                
                // Transformer tr = TransformerFactory.newInstance().newTransformer();
                DOMSource source = new DOMSource(document);
                
                StringWriter writer = new StringWriter();
                StreamResult result = new StreamResult(writer);
                TransformerFactory tf = TransformerFactory.newInstance();
                Transformer transformer = tf.newTransformer();
                transformer.transform(source, result);
                
                xmlStr1 = writer.toString();
                
                LOG.info("xmlStr1 = {}", xmlStr1);
            }
            
            {
                DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
                ///Document document = documentBuilder.parse(xmlStr1);
                ///Document document = xmlStr1.parse(new InputSource(new StringReader(xmlStr1)));                
                
                Document document = documentBuilder.parse(new InputSource(new StringReader(xmlStr1)));

                Element signature_ws_element =  document.createElement("signature_ws");
                signature_ws_element.setTextContent(signBase64_1);                
                
                Element uid_passw_element = document.getDocumentElement();
                
                uid_passw_element.appendChild(signature_ws_element);
                
                // Transformer tr = TransformerFactory.newInstance().newTransformer();
                DOMSource source = new DOMSource(document);
                
                StringWriter writer = new StringWriter();
                StreamResult result = new StreamResult(writer);
                TransformerFactory tf = TransformerFactory.newInstance();
                Transformer transformer = tf.newTransformer();
                transformer.transform(source, result);
                
                xmlStr2 = writer.toString();
                
                LOG.info("xmlStr2 = {}", xmlStr2);            
            }
            
            {
                KeyPairGenerator keyGen = null;

                ECGenParameterSpec eccGen = new ECGenParameterSpec("secp256r1");

                keyGen = KeyPairGenerator.getInstance("EC", provider);
                keyGen.initialize(eccGen, new SecureRandom());

                // Generate the key
                KeyPair keyPair = keyGen.generateKeyPair();
                PrivateKey privateKey = keyPair.getPrivate();
                PublicKey publicKey = keyPair.getPublic();

                Signature signer = Signature.getInstance("SHA256WITHECDSA", provider);
                signer.initSign(privateKey);

                signer.update(base64Decoder.decode(signBase64_1.getBytes()));
                // signer.update(signBase64_1.getBytes());
                byte[] sign = signer.sign();

                signBase64_2 = new String(base64Encoder.encode(sign));

                LOG.info("signBase64 = {}", signBase64_2);
                LOG.info("signBase64.length() = {}", signBase64_2.length());

                byte[] signDec = base64Decoder.decode(signBase64_2.getBytes());

                Signature signerVerify = Signature.getInstance("SHA256WITHECDSA", provider);
                signerVerify.initVerify(publicKey);

                signerVerify.update(base64Decoder.decode(signBase64_1.getBytes()));
                //signerVerify.update(signBase64_2.getBytes());
                boolean verifyRes = signerVerify.verify(signDec);

                LOG.info("verifyRes = {}", verifyRes);
            }
            
            {
                DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
                ///Document document = documentBuilder.parse(xmlStr1);
                ///Document document = xmlStr1.parse(new InputSource(new StringReader(xmlStr1)));                
                
                Document document = documentBuilder.parse(new InputSource(new StringReader(xmlStr2)));

                Element signature_api_element =  document.createElement("signature_api");
                signature_api_element.setTextContent(signBase64_2);
                
                Element uid_passw_element = document.getDocumentElement();
                
                uid_passw_element.appendChild(signature_api_element);
                
                // Transformer tr = TransformerFactory.newInstance().newTransformer();
                DOMSource source = new DOMSource(document);
                
                StringWriter writer = new StringWriter();
                StreamResult result = new StreamResult(writer);
                TransformerFactory tf = TransformerFactory.newInstance();
                Transformer transformer = tf.newTransformer();
                transformer.transform(source, result);
                
                xmlStr3 = writer.toString();
                
                LOG.info("xmlStr3 = {}", xmlStr3);            
            }
            
            byte [] digestSign_2 = null;
            String digestStr_2;
            
            {
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256", "BC");
                messageDigest.update(base64Decoder.decode(signBase64_2.getBytes()));
                digestSign_2 = messageDigest.digest();
                
                digestStr_2 = new String(base64Encoder.encode(digestSign_2));
                
                LOG.info("digestStr_2 = {}", digestStr_2);                
            }
            
            {
                DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
                ///Document document = documentBuilder.parse(xmlStr1);
                ///Document document = xmlStr1.parse(new InputSource(new StringReader(xmlStr1)));                
                
                Document document = documentBuilder.parse(new InputSource(new StringReader(xmlStr3)));

                Element digest_signature_api_element =  document.createElement("digest_signature_api");
                digest_signature_api_element.setTextContent(digestStr_2);                
                
                Element uid_passw_element = document.getDocumentElement();
                
                uid_passw_element.appendChild(digest_signature_api_element);
                
                // Transformer tr = TransformerFactory.newInstance().newTransformer();
                DOMSource source = new DOMSource(document);
                
                StringWriter writer = new StringWriter();
                StreamResult result = new StreamResult(writer);
                TransformerFactory tf = TransformerFactory.newInstance();
                Transformer transformer = tf.newTransformer();
                transformer.transform(source, result);
                
                xmlStr4 = writer.toString();
                
                LOG.info("xmlStr4 = {}", xmlStr4);
            }
            
            byte[] encrText = null;
            String encrTextBase64 = null;
            byte[] ivArray = null;
            String encSalt = null;
            
            int iterationCount;
            
            {
                SecureRandom random = new SecureRandom();
                ivArray = new byte[DEF_AES_KEY_LENGTH];
                random.nextBytes(ivArray);
                
                char[] secretKeyArray = new char[DEF_AES_KEY_LENGTH];
                System.arraycopy(digestStr_2.toCharArray(), 0, secretKeyArray, 0, secretKeyArray.length);
                
                encSalt = new RandomStringGen(DEF_AES_KEY_LENGTH, RandomStringGen.DEF_MODE_ALL).nextString();
                
                //final PBEKeySpec spec = new PBEKeySpec(secretKeyArray, encSalt.getBytes(), 1000, DEF_AES_KEY_LENGTH*8);
                
                iterationCount = 500 + random.nextInt() % 1000;
                LOG.info("iterationCount = {}", iterationCount);                
                
                final PBEKeySpec spec = new PBEKeySpec(secretKeyArray, encSalt.getBytes(), iterationCount, DEF_AES_KEY_LENGTH*8);
                final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", provider);
                
                SecretKey curSecretKey = keyFactory.generateSecret(spec);

                final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);

                LOG.info("curSecretKey.getAlgorithm() = {}", curSecretKey.getAlgorithm());                
                LOG.info("curSecretKey.getFormat() = {}", curSecretKey.getFormat());                
                LOG.info("curSecretKey.getEncoded().length = {}", curSecretKey.getEncoded().length);                
                
                cipher.init(Cipher.ENCRYPT_MODE, curSecretKey, new IvParameterSpec(ivArray));                
                
                encrText = cipher.doFinal(password.getBytes());
                
                encrTextBase64 = new String(base64Encoder.encode(encrText));
                
                LOG.info("encrTextBase64 = {}", encrTextBase64);                
            }
            
            {
                DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
                ///Document document = documentBuilder.parse(xmlStr1);
                ///Document document = xmlStr1.parse(new InputSource(new StringReader(xmlStr1)));                
                
                Document document = documentBuilder.parse(new InputSource(new StringReader(xmlStr4)));

                Element enc_passw_element =  document.createElement("enc_passw");
                enc_passw_element.setTextContent(encrTextBase64);
                
                Element iv_element =  document.createElement("iv");
                iv_element.setTextContent(new String(base64Encoder.encode(ivArray)));

                Element salt_element =  document.createElement("salt");
                salt_element.setTextContent(new String(base64Encoder.encode(encSalt.getBytes())));

                Element uid_passw_element = document.getDocumentElement();

                uid_passw_element.appendChild(iv_element);
                uid_passw_element.appendChild(salt_element);
                uid_passw_element.appendChild(enc_passw_element);

                // Transformer tr = TransformerFactory.newInstance().newTransformer();
                DOMSource source = new DOMSource(document);

                StringWriter writer = new StringWriter();
                StreamResult result = new StreamResult(writer);
                TransformerFactory tf = TransformerFactory.newInstance();
                Transformer transformer = tf.newTransformer();
                transformer.transform(source, result);

                xmlStr5 = writer.toString();

                LOG.info("xmlStr5 = {}", xmlStr5);
            }
            
            byte[] decrText = null;
            String decrTextBase64;
            
            {
                SecureRandom random = new SecureRandom();
                
                char[] secretKeyArray = new char[DEF_AES_KEY_LENGTH];
                System.arraycopy(digestStr_2.toCharArray(), 0, secretKeyArray, 0, secretKeyArray.length);
                
                //final PBEKeySpec spec = new PBEKeySpec(secretKeyArray, encSalt.getBytes(), 1000, DEF_AES_KEY_LENGTH*8);
                
                // int iterationCount = 500 + random.nextInt() % 1000;
                LOG.info("iterationCount = {}", iterationCount);                
                
                final PBEKeySpec spec = new PBEKeySpec(secretKeyArray, encSalt.getBytes(), iterationCount, DEF_AES_KEY_LENGTH*8);
                
                final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", provider);
                
                SecretKey curSecretKey = keyFactory.generateSecret(spec);

                final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);

                LOG.info("curSecretKey.getAlgorithm() = {}", curSecretKey.getAlgorithm());                
                LOG.info("curSecretKey.getFormat() = {}", curSecretKey.getFormat());                
                LOG.info("curSecretKey.getEncoded().length = {}", curSecretKey.getEncoded().length);                
                
                cipher.init(Cipher.DECRYPT_MODE, curSecretKey, new IvParameterSpec(ivArray));                
                
                decrText = cipher.doFinal(base64Decoder.decode(encrTextBase64));
                
                decrTextBase64 = new String(base64Encoder.encode(decrText));
                
                LOG.info("decrTextBase64 = {}", decrTextBase64);                
            }
            
            {
                DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
                
                Document document = documentBuilder.parse(new InputSource(new StringReader(xmlStr5)));

                Element decr_passw_element =  document.createElement("decr_passw");
                decr_passw_element.setTextContent(decrTextBase64);                

                Element uid_passw_element = document.getDocumentElement();

                uid_passw_element.appendChild(decr_passw_element);

                // Transformer tr = TransformerFactory.newInstance().newTransformer();
                DOMSource source = new DOMSource(document);

                StringWriter writer = new StringWriter();
                StreamResult result = new StreamResult(writer);
                TransformerFactory tf = TransformerFactory.newInstance();
                Transformer transformer = tf.newTransformer();
                transformer.transform(source, result);

                xmlStr6 = writer.toString();

                LOG.info("xmlStr6 = {}", xmlStr6);
            }
*/
            
            LOG.info("Application uid-pw-enc finished...");            
    
            // --------------------
            
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
        } catch (NoSuchProviderException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (InvalidKeySpecException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (NoSuchPaddingException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (IllegalBlockSizeException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (BadPaddingException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        }
        
/*        
        catch (InterruptedException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        }        
        catch (NoSuchAlgorithmException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (InvalidAlgorithmParameterException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (InvalidKeyException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (SignatureException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (ParserConfigurationException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (TransformerConfigurationException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (TransformerFactoryConfigurationError e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (TransformerException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (SAXException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (IOException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (NoSuchProviderException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (InvalidKeySpecException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (NoSuchPaddingException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (IllegalBlockSizeException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (BadPaddingException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (KeyStoreException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (CertificateException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (OperatorCreationException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);            
        } catch (UnrecoverableKeyException e) {
            LOG.error(PrintTools.stackTraceToString(e), e);
        }
*/        
    }
    
}


