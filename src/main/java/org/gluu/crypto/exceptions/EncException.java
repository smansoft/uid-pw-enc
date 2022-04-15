/**
 * 
 */
package org.gluu.crypto.exceptions;

/**
 * EncException.
 * 
 * @author SMan
 * @version 2022-04-11
 *
 */
public class EncException extends Exception {

    /**
     * 
     */
    private static final long serialVersionUID = 5884634853990759188L;

    /**
     * 
     */
    public EncException() {
    }

    /**
     * 
     * @param message
     */
    public EncException(String message) {
        super(message);
    }

    /**
     * 
     * @param message
     * @param cause
     */
    public EncException(String message, Throwable cause) {
        super(message, cause);
    }
}
