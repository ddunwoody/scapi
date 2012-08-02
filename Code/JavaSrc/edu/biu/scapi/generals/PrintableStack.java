/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
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
