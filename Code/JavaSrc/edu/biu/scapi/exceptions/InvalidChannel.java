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
 * This exception class inherits from RuntimeException. There is no way to continue if this exception is thrown. The code must be corrected.
 * Having to declare such exceptions would not aid significantly in establishing the correctness of the application.
 */
package edu.biu.scapi.exceptions;

/**
 * @author LabTest
 *
 */
public class InvalidChannel extends RuntimeException{


	private static final long serialVersionUID = -9060767436209580708L;


	public InvalidChannel() {
		// TODO Auto-generated constructor stub
	}
	
	public InvalidChannel(String message){
		super(message);
	}
}
