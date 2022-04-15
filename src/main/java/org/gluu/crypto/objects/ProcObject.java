/**
 * 
 */
package org.gluu.crypto.objects;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
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

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.operator.OperatorCreationException;
import org.gluu.crypto.primitives.EcSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Base (abstract) class of processing classes.   
 * 
 * @author SMan
 * @version 2022-04-11
 */
public abstract class ProcObject {

    @SuppressWarnings("unused")
    private static final Logger LOG = LoggerFactory.getLogger(ProcObject.class);

    private static int DEF_CERTIFICATE_PERIOD = 1; // years

    /**
     * 
     * @author SMan
     * @version 2022-04-11
     */
    public static class ProcData {

        public String uidBase64;
        public String passwordBase64;

        public String webSiteEcPrivateKeyBase64;
        public String webSiteEcPublicKeyBase64;
        public String webSiteSignatureBase64;

        public String apiEcPrivateKeyBase64;
        public String apiEcPublicKeyBase64;
        public String apiSignatureBase64;

        public String encSaltBase64;
        public String secretKeyBase64;

        public String ivBase64;
        public String srcDataBase64;
        public String encDataBase64;
        public String decDataBase64;

        /**
         * 
         */
        public ProcData() {
        }

        /**
         * 
         * @param xmlProcData
         * @throws ParserConfigurationException
         * @throws IOException
         * @throws SAXException
         */
        public void fromXML(final String xmlProcData) throws ParserConfigurationException, SAXException, IOException {

            DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document document = documentBuilder.parse(new InputSource(new StringReader(xmlProcData)));

            Element proc_data_element = document.getDocumentElement();

            NodeList childNodes = proc_data_element.getChildNodes();

            for (int i = 0; i < childNodes.getLength(); i++) {
                Node node = (Node) childNodes.item(i);
                if (node instanceof Element) {
                    String nodeName = node.getNodeName();
                    String nodeText = node.getTextContent();
                    switch (nodeName) {
                    case "uid":
                        uidBase64 = nodeText;
                        break;
                    case "password":
                        passwordBase64 = nodeText;
                        break;
                    case "web_site_ec_private_key":
                        webSiteEcPrivateKeyBase64 = nodeText;
                        break;
                    case "web_site_ec_public_key":
                        webSiteEcPublicKeyBase64 = nodeText;
                        break;
                    case "web_site_signature":
                        webSiteSignatureBase64 = nodeText;
                        break;
                    case "api_ec_private_key":
                        apiEcPrivateKeyBase64 = nodeText;
                        break;
                    case "api_ec_public_key":
                        apiEcPublicKeyBase64 = nodeText;
                        break;
                    case "api_signature":
                        apiSignatureBase64 = nodeText;
                        break;
                    case "enc_salt":
                        encSaltBase64 = nodeText;
                        break;
                    case "secret_key":
                        secretKeyBase64 = nodeText;
                        break;
                    case "iv":
                        ivBase64 = nodeText;
                        break;
                    case "src_data":
                        srcDataBase64 = nodeText;
                        break;
                    case "enc_data":
                        encDataBase64 = nodeText;
                        break;
                    case "dec_data":
                        decDataBase64 = nodeText;
                        break;
                        
                    }
                }
            }
        }

        /**
         * 
         * @return
         * @throws ParserConfigurationException
         * @throws TransformerException
         */
        public String toXML() throws ParserConfigurationException, TransformerException {

            DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document document = documentBuilder.newDocument();

            Element proc_data_element = document.createElement("proc_data");

            document.appendChild(proc_data_element);

            Element uid_element = document.createElement("uid");
            Element password_element = document.createElement("password");

            Element web_site_ec_private_key_element = document.createElement("web_site_ec_private_key");
            Element web_site_ec_public_key_element = document.createElement("web_site_ec_public_key");
            Element web_site_signature_element = document.createElement("web_site_signature");

            Element api_ec_private_key_element = document.createElement("api_ec_private_key");
            Element api_ec_public_key_element = document.createElement("api_ec_public_key");
            Element api_signature_element = document.createElement("api_signature");

            Element enc_salt_element = document.createElement("enc_salt");
            Element secret_key_element = document.createElement("secret_key");

            Element iv_element = document.createElement("iv");
            Element src_data_element = document.createElement("src_data");
            Element enc_data_element = document.createElement("enc_data");
            Element dec_data_element = document.createElement("dec_data");

            proc_data_element.appendChild(uid_element);
            proc_data_element.appendChild(password_element);

            proc_data_element.appendChild(web_site_ec_private_key_element);
            proc_data_element.appendChild(web_site_ec_public_key_element);
            proc_data_element.appendChild(web_site_signature_element);

            proc_data_element.appendChild(api_ec_private_key_element);
            proc_data_element.appendChild(api_ec_public_key_element);
            proc_data_element.appendChild(api_signature_element);

            proc_data_element.appendChild(enc_salt_element);
            proc_data_element.appendChild(secret_key_element);

            proc_data_element.appendChild(iv_element);
            proc_data_element.appendChild(src_data_element);
            proc_data_element.appendChild(enc_data_element);
            proc_data_element.appendChild(dec_data_element);

            uid_element.setTextContent(uidBase64);
            password_element.setTextContent(passwordBase64);

            web_site_ec_private_key_element.setTextContent(webSiteEcPrivateKeyBase64);
            web_site_ec_public_key_element.setTextContent(webSiteEcPublicKeyBase64);
            web_site_signature_element.setTextContent(webSiteSignatureBase64);

            api_ec_private_key_element.setTextContent(apiEcPrivateKeyBase64);
            api_ec_public_key_element.setTextContent(apiEcPublicKeyBase64);
            api_signature_element.setTextContent(apiSignatureBase64);

            enc_salt_element.setTextContent(encSaltBase64);
            secret_key_element.setTextContent(secretKeyBase64);

            iv_element.setTextContent(ivBase64);
            src_data_element.setTextContent(srcDataBase64);
            enc_data_element.setTextContent(encDataBase64);
            dec_data_element.setTextContent(decDataBase64);

            DOMSource source = new DOMSource(document);

            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.STANDALONE, "yes");
            transformer.transform(source, result);

            return writer.toString();
        }
    }

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
    public void genSignKeys() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, CertificateException,
            KeyStoreException, OperatorCreationException, IOException {
        File ksFile = new File(this.ecSigner.getKsFPath());
        if (ksFile.exists()) {
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

        if (!this.ecSigner.containsKeyAlias(this.ksAlias)) {
            throw new KeyStoreException(String.format("Alias %s not found", this.ksAlias));
        }
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
    public String signData(final String inDataBase64) throws UnrecoverableKeyException, InvalidKeyException,
            KeyStoreException, NoSuchAlgorithmException, SignatureException {
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
    public boolean verifyData(final String inDataBase64, final String idSingBase64) throws UnrecoverableKeyException,
            InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, SignatureException {
        return this.ecSigner.verify(this.ksAlias, inDataBase64, idSingBase64);
    }
}
