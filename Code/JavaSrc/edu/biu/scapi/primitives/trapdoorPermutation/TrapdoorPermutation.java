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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/** 
 * This interface is the general interface of trapdoor permutation. Every class in this family should implement this interface.
 * 
 * A trapdoor permutation is a bijection (1-1 and onto function) that is easy to compute for everyone, 
 * yet is hard to invert unless given special additional information, called the "trapdoor". 
 * The public key is essentially the function description and the private key is the trapdoor.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
  */
public interface TrapdoorPermutation {
	
	/**
	 * Sets this trapdoor permutation with public key and private key.
	 * @param publicKey
	 * @param privateKey
	 */
	public void setKey(PublicKey publicKey, PrivateKey privateKey)throws InvalidKeyException;
	
	/**
	 * Sets this trapdoor permutation with a public key<p> 
	 * After this initialization, this object can do compute but not invert.
	 * This initialization is for user that wants to encrypt a message using the public key but deosn't want to decrypt a message.
	 * @param publicKey
	 */
	public void setKey(PublicKey publicKey)throws InvalidKeyException;
	
	/**
	 * Checks if this trapdoor permutation object has been previously initialized.<p> 
	 * To initialize the object the setKey function has to be called with corresponding parameters after construction.
	 * 
	 * @return <code>true</code> if the object was initialized;<p>
	 * 		   <code>false</code> otherwise.
	 */
	public boolean isKeySet();

	/** 
	 * @return the public key
	 */
	public PublicKey getPubKey();
	
	
	/** 
	 * @return the algorithm name. for example - RSA, Rabin.
	 */
	public String getAlgorithmName();

	/**
	 * Generates public and private keys for this trapdoor permutation.
	 * @param keyParams hold the required parameters
	 * @return KeyPair holding the public and private keys
	 * @throws InvalidParameterSpecException 
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException;
	
	/**
	 * Generates public and private keys for this trapdoor permutation.
	 * @return KeyPair holding the public and private keys
	 * @throws InvalidParameterSpecException 
	 */
	public KeyPair generateKey();
	
	/** 
	 * Computes the operation of this trapdoor permutation on the given TPElement.
	 * @param tpEl - the input for the computation
	 * @return - the result TPElement from the computation
	 * @throws IllegalArgumentException if the given element is invalid for this permutation
	 */
	public TPElement compute(TPElement tpEl) throws IllegalArgumentException;

	/** 
	 * Inverts the operation of this trapdoor permutation on the given TPElement.
	 * @param tpEl - the input to invert
	 * @return - the result TPElement from the invert operation
	 * @throws KeyException if there is no private key
	 * @throws IllegalArgumentException if the given element is invalid for this permutation
	 */
	public TPElement invert(TPElement tpEl) throws KeyException;

	/** 
	 * Computes the hard core predicate of the given tpElement. <p>
	 * A hard-core predicate of a one-way function f is a predicate b (i.e., a function whose output is a single bit) 
	 * which is easy to compute given x but is hard to compute given f(x).
	 * In formal terms, there is no probabilistic polynomial time algorithm that computes b(x) from f(x) 
	 * with probability significantly greater than one half over random choice of x.
	 * @param tpEl the input to the hard core predicate
	 * @return byte the hard core predicate. In java, the smallest types are boolean and byte. 
	 * We chose to return a byte since many times we need to concatenate the result of various predicates 
	 * and it will be easier with a byte than with a boolean.
	 */
	public byte hardCorePredicate(TPElement tpEl);

	/** 
	 * Computes the hard core function of the given tpElement.
	 * A hard-core function of a one-way function f is a function g 
	 * which is easy to compute given x but is hard to compute given f(x).
	 * In formal terms, there is no probabilistic polynomial time algorithm that computes g(x) from f(x) 
	 * with probability significantly greater than one half over random choice of x.
	 * @param tpEl the input to the hard core function
	 * @return byte[] the result of the hard core function
	 */
	public byte[] hardCoreFunction(TPElement tpEl);
	
	
	/** 
	 * Checks if the given element is valid for this trapdoor permutation
	 * @param tpEl - the element to check
	 * @return TPElValidity - enum number that indicate the validation of the element.
	 * There are three possible validity values: 
	 * VALID (it is an element)
	 * NOT_VALID (it is not an element)
	 * DON’T_KNOW (there is not enough information to check if it is an element or not)  
	 * @throws IllegalArgumentException if the given element is invalid for this permutation
	 */
	public TPElValidity isElement(TPElement tpEl) throws IllegalArgumentException;
	
	/** 
	 * creates a random TPElement that is valid for this trapdoor permutation
	 * @return TPElement - the created random element 
	 */
	public TPElement generateRandomTPElement();
	
	/** 
	 * Creates a TPElement from a specific value x. It checks that the x value is valid for this trapdoor permutation.
	 * @return TPElement - If the x value is valid for this permutation return the created random element
	 * @throws  IllegalArgumentException if the given value x is invalid for this permutation
	 */
	public TPElement generateTPElement(BigInteger x) throws IllegalArgumentException;
	
	/** 
	 * Creates a TPElement from a specific value x. This function does not guarantee that the the returned "TPElement" is valid.<p>
	 * It is the caller's responsibility to pass a legal x value.
	 * @return TPElement - Set the x value and return the created random element
	 */
	public TPElement generateUncheckedTPElement(BigInteger x);
	
}
