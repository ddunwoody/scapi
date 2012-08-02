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
package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;

/**
 * General interface for DamgardJurik encryption scheme. Every concrete implementation of DamgardJurik encryption should implement this interface.
 * By definition, this encryption scheme is CPA-secure and Indistinguishable.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface DamgardJurikEnc extends AsymAdditiveHomomorphicEnc {
	
	/**
	 * This function takes an encryption of some plaintext (let's call it originalPlaintext) and returns a cipher that "looks" different but
	 * it is also an encryption of originalPlaintext.<p>
	 * @param cipher
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given ciphertext does not match this asymmetric encryption.
	 */
	public AsymmetricCiphertext reRandomize(AsymmetricCiphertext cipher);
}
