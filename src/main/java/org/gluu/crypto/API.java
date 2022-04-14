/**
 * 
 */
package org.gluu.crypto;

/**
 * 
 * @author SMan
 * @version 2022-04-11
 */
public class API extends ProcObject {

    /**
     * 
     * @param ecSigner
     * @param ksAlias
     * @param dnName
     */
    public API(final EcSigner ecSigner, final String ksAlias, final String dnName) {
        super(ecSigner);
        
        setKsAlias(ksAlias);
        setDnName(dnName);
    }    

}
