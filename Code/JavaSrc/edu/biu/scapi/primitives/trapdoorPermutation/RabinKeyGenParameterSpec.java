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
package edu.biu.scapi.primitives.trapdoorPermutation;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Interface for RabinParameterSpec
 *
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public class RabinKeyGenParameterSpec implements AlgorithmParameterSpec{
	int keySize;
	
	/**
	 * Constructor that set the keybits
	 * @param keySize
	 */
	public RabinKeyGenParameterSpec(int keySize) {
		if (keySize<16){
			throw new IllegalArgumentException("Rabin Key size should be greater than 15");
		}
		this.keySize = keySize;
	}
	
	/**
	 * @return int - The key bits size
	 */
	public int getKeySize() {
		return keySize;
	}
}
