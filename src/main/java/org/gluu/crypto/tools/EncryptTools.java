/**
 * 
 */
package org.gluu.crypto.tools;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * EncryptTools, tools class.
 *  
 * @author SMan
 * @version 2022-04-11
 */
public abstract class EncryptTools {
    
    private static final Logger LOG = LoggerFactory.getLogger(EncryptTools.class);
    
    private static Provider provider;    

    static {
        try {
            EncryptTools.provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
        catch (Exception e) {
            EncryptTools.provider = null;
            LOG.error(PrintTools.stackTraceToString(e), e);            
        }
    }

    /**
     * 
     * @return
     */
    static public Provider getProvider() {
        return EncryptTools.provider;
    }
    
}
