/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.math.BigInteger;

import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;

/**
 * Interface for asymmetric multiplicative homomorphic encryption.
 * Such encryption schemes can compute the encryption of m1*m2, given only the public key and the encryptions of m1 and m2.
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface AsymMultiplicativeHomomorphicEnc extends AsymmetricEnc{

	/**
	 * Receives two ciphertexts and return their multiplication
	 * @param cipher1
	 * @param cipher2
	 * @return the multiplication result
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given ciphertexts do not match this asymmetric encryption.
	 */
	public AsymmetricCiphertext multiply(AsymmetricCiphertext cipher1, AsymmetricCiphertext cipher2);
	
	/**
	 * Receives two ciphertexts and return their multiplication.<p>
	 * There are cases when the random value is used after the function, for example, in sigma protocol. 
	 * In these cases the random value should be known to the user. We decided not to have function that return it to the user 
	 * since this can cause problems when the multiply function is called more than one time. 
	 * Instead, we decided to have an additional multiply function that gets the random value from the user.
	 * @param cipher1
	 * @param cipher2
	 * @param r The random value used in the function.
	 * @return the multiplication result
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given ciphertexts do not match this asymmetric encryption.
	 */
	public AsymmetricCiphertext multiply(AsymmetricCiphertext cipher1, AsymmetricCiphertext cipher2, BigInteger r);
}
