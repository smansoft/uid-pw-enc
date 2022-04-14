/**
 * 
 */
package org.gluu.crypto;

/**
 * 
 * @author SMan
 * @version 2022-04-11
 */
public class WebSite extends ProcObject {

    /**
     * 
     * @param ecSigner
     * @param ksAlias
     * @param dnName
     */
    public WebSite(final EcSigner ecSigner, final String ksAlias, final String dnName) {
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
