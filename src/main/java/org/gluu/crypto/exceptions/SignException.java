/**
 * 
 */
package org.gluu.crypto.exceptions;

/**
 * SignException
 * 
 * @author SMan
 * @version 2022-04-11
 *
 */
public class SignException extends Exception {
    
    /**
     * 
     */
    private static final long serialVersionUID = 2620227450294596231L;

    /**
     * 
     */
    public SignException() {
    }

    /**
     * 
     * @param message
     */
    public SignException(String message) {
        super(message);
    }

    /**
     * 
     * @param message
     * @param cause
     */
    public SignException(String message, Throwable cause) {
        super(message, cause);
    }

}
