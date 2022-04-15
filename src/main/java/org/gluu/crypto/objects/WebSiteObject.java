/**
 * 
 */
package org.gluu.crypto.objects;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Base64;

import org.gluu.crypto.primitives.EcSigner;
import org.gluu.crypto.tools.RandomStringGen;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author SMan
 * @version 2022-04-11
 */
public class WebSiteObject extends ProcObject {
    
    @SuppressWarnings("unused")
    private static final Logger LOG = LoggerFactory.getLogger(WebSiteObject.class);

    /**
     * 
     * @param ecSigner
     * @param ksAlias
     * @param dnName
     */
    public WebSiteObject(final EcSigner ecSigner, final String ksAlias, final String dnName) {
        super(ecSigner);
        
        setKsAlias(ksAlias);
        setDnName(dnName);
    }

    /**
     * 
     * @param procData
     */
    public void genUidAndPassw(final ProcData procData) {
        procData.uidBase64 = Base64.getEncoder().encodeToString(new RandomStringGen(8, RandomStringGen.DEF_MODE_DIGITS).nextString().getBytes());
        procData.passwordBase64 =  Base64.getEncoder().encodeToString(new RandomStringGen(21, RandomStringGen.DEF_MODE_ALL).nextString().getBytes());
    }
    
    /**
     * 
     * @param procData
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws UnrecoverableKeyException 
     */
    public void initEcSignatureKeys(final ProcData procData) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        procData.webSiteEcPrivateKeyBase64 = Base64.getEncoder().encodeToString(getEcSigner().getECKeyPair(getKsAlias()).getPrivate().getEncoded());                
        procData.webSiteEcPublicKeyBase64 = Base64.getEncoder().encodeToString(getEcSigner().getECKeyPair(getKsAlias()).getPublic().getEncoded());
    }
    
}
