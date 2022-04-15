/**
 * 
 */
package org.gluu.crypto.objects;

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
     */
    public void genUidAndPassw() {
        
        String uid = new RandomStringGen(8, RandomStringGen.DEF_MODE_DIGITS).nextString();
        String password = new RandomStringGen(21, RandomStringGen.DEF_MODE_ALL).nextString();
        
        setUid(uid);
        setPassword(password);
        
    }

}
