/**
 * 
 */
package org.gluu.crypto.objects;

import java.util.Base64;

import org.gluu.crypto.primitives.EcSigner;
import org.gluu.crypto.tools.RandomStringGen;

/**
 * 
 * @author SMan
 * @version 2022-04-11
 */
public class WebSiteObject extends ProcObject {

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
    public void genUidAndPassw(ProcData procData) {
        procData.uidBase64 = Base64.getEncoder().encodeToString(new RandomStringGen(8, RandomStringGen.DEF_MODE_DIGITS).nextString().getBytes());
        procData.passwordBase64 =  Base64.getEncoder().encodeToString(new RandomStringGen(21, RandomStringGen.DEF_MODE_ALL).nextString().getBytes());
    }
    
}
