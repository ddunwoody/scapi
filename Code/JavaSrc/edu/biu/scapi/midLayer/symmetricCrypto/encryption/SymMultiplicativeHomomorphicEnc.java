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
package edu.biu.scapi.midLayer.symmetricCrypto.encryption;

import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;

/**
 * General interface for symmetric multiplicative homomorphic encryption.
 * Such encryption scheme can compute the encryption of m1*m2, given only the encryptions of m1 and m2.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface SymMultiplicativeHomomorphicEnc extends SymmetricEnc {

	/**
	 * Given two ciphers c1 = enc(p1), c2 = enc(p2) this function returns c1 * c2 = enc(p1 * p2)
	 * @param c1 the encryption of p1
	 * @param c2 the encryption of p2
	 * @return the multiplication of c1 and c2.
	 */
	public SymmetricCiphertext multiply(SymmetricCiphertext c1, SymmetricCiphertext c2);
}
