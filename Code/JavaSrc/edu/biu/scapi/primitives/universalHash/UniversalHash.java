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
package edu.biu.scapi.primitives.universalHash;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

/** 
 * General interface for perfect universal hash. Every class in this family should implement this interface.
 * 
 * A universal hash function is a family of hash functions (as in the sense of hash functions for data structures) with the property that 
 * a randomly chosen hash function (from the family) yields very few collisions, with good probability. 
 * More importantly in a cryptographic context, universal hash functions have important properties, like good randomness extraction and 
 * pairwise independence. Many universal families are known (for hashing integers, vectors, strings), and their evaluation is often very efficient.
 * The notions of perfect universal hashing and collision resistance hash are distinct, and should not be confused (it is unfortunate that they 
 * have a similar name). We therefore completely separate the two implementations so that collision-resistant hash functions cannot be confused 
 * with perfect universal hash functions.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface UniversalHash {
	
	/**
	 * Sets the secret key for this UH.
	 * The key can be changed at any time. 
	 * @param secretKey secret key
	 * @throws InvalidKeyException 
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException;
	
	/**
	 * An object trying to use an instance of UH needs to check if it has already been initialized.
	 * @return true if the object was initialized by calling the function setKey.
	 */
	public boolean isKeySet();
	
	/** 
	 * @return the algorithm name
	 */
	public String getAlgorithmName();

	/** 
	 * This function has multiple roles depending on the concrete hash function.
	 * If the concrete class can get a varying input lengths then there are 2 possible answers:
	 * 1. The maximum size of the input – if there is some kind of an upper bound on the input size 
	 * (for example in the EvaluationHashFunction there is a limit on the input size due to security reasons) 
	 * thus, this function returns this bound even though the actual size can be any number between zero and that limit.
	 * 2. Zero – if there is no limit on the input than this function returns 0.
	 * If the concrete class can get a fixed length, this function returns a constant size that may be determined either in the init 
	 * for some implementations or hardcoded for other implementations.

	 * @return the input size of this hash function
	 */
	public int getInputSize();

	/** 
	 * @return the output size of this hash function
	 */
	public int getOutputSize();
	
	/**
	 * Generates a secret key to initialize this UH object.
	 * @param keyParams algorithmParameterSpec contains the required parameters for the key generation
	 * @return the generated secret key
	 * @throws InvalidParameterSpecException 
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException;
	
	/**
	 * Generates a secret key to initialize this UH object.
	 * @param keySize is the required secret key size in bits 
	 * @return the generated secret key 
	 */
	public SecretKey generateKey(int keySize);

	/** 
	 * Computes the hash function on the in byte array and put the result in the output byte array
	 * @param in - input byte array
	 * @param inOffset - the offset within the input byte array
	 * @param inLen - length. The number of bytes to take after the offset
	 * @param out - output byte array
	 * @param outOffset - the offset within the output byte array
	 * @throws IllegalBlockSizeException if the input length is greater than the upper limit
	 */
	public void compute(byte[] in, int inOffset, int inLen, byte[] out,
			int outOffset) throws IllegalBlockSizeException;
}
