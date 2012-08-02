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
package edu.biu.scapi.primitives.kdf;

import javax.crypto.SecretKey;

/** 
 * General interface of key derivation function. Every class in this family should implement this interface. <p>
 * A key derivation function (or KDF) is used to derive (close to) uniformly distributed string/s from a secret value 
 * with high entropy (but no other guarantee regarding its distribution). 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface KeyDerivationFunction {
	
	/** 
	 * Generates a new secret key from the given seed.
	 * @param entropySource the secret key that is the seed for the key generation
	 * @param inOff the offset within the entropySource to take the bytes from
	 * @param inLen the length of the seed
	 * @param outLen the required output key length
	 * @return SecretKey the derivated key.
	 */
	public SecretKey derivateKey(byte[] entropySource, int inOff, int inLen, int outLen);
	
	/** 
	 * Generates a new secret key from the given seed and iv.
	 * @param entropySource the secret key that is the seed for the key generation
	 * @param inOff the offset within the entropySource to take the bytes from
	 * @param inLen the length of the seed
	 * @param outLen the required output key length
	 * @param iv info for the key generation
	 * @return SecretKey the derivated key.
	 */
	public SecretKey derivateKey(byte[] entropySource, int inOff, int inLen, int outLen, byte[] iv);
}
