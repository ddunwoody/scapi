/**
 * 
 */
package edu.biu.scapi.generals;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;

/**
 * This class is a debugger helper. It lets us print the stack anywhere in the code.
 * Usage: 
 * 1) Define a throwable variable like the member of this class.
 * 2) Call System.out.println( getStackTrace(throwable) ); wherever you need to print the stack so far.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class PrintableStack {
	final Throwable throwable = new IllegalArgumentException("Hello");
	
	public static String getStackTrace(Throwable throwable) {
		   Writer writer = new StringWriter();
		   PrintWriter printWriter = new PrintWriter(writer);
		   throwable.printStackTrace(printWriter);
		   return writer.toString();
		   }
}
