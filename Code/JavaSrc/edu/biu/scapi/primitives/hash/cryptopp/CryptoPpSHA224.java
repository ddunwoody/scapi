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
package edu.biu.scapi.primitives.hash.cryptopp;

import edu.biu.scapi.primitives.hash.SHA224;

/** 
 * Concrete class of cryptographicHash for SHA224. This class wraps crypto++ implementation of SHA224.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class CryptoPpSHA224 extends CryptoPpHash implements SHA224 {

	
	/**
	 * Passes the hash name to the super class which does the hash computation
	 */
	public CryptoPpSHA224() {
		//calls the super constructor with the name of the hash - SHA224.
		super("SHA224");
	}

}
