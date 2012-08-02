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
package edu.biu.scapi.midLayer.symmetricCrypto.keys;

import java.security.spec.AlgorithmParameterSpec;

/**
 * This class is a container for the data needed to generate a key for Authenticated Encryption.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class AuthEncKeyGenParameterSpec implements AlgorithmParameterSpec {

		private int encKeySize;
		private int macKeySize;
		
		public AuthEncKeyGenParameterSpec(int encKeySize, int macKeySize){
			this.encKeySize = encKeySize;
			this.macKeySize = macKeySize;
		}
		
		public int getEncKeySize() {
			return encKeySize;
		}
		
		public int getMacKeySize() {
			return macKeySize;
		}
}
