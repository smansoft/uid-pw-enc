/**
 * 
 */
package org.gluu.crypto.tools;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

/**
 * PrintTools, tools class.
 *
 *
 * @author Sergey Manoylo
 * @version 2022-04-10
 */
public abstract class PrintTools {
    
    /**
     * 
     * @param ex
     * @return
     */
    public static String stackTraceToString(Throwable ex) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(byteArrayOutputStream);
        printStream.println(ex.toString());
        StackTraceElement[] stacks = ex.getStackTrace();
        for (StackTraceElement stack : stacks) {
            printStream.println(stack.toString());
        }
        printStream.flush();
        return byteArrayOutputStream.toString();
    }    

}
