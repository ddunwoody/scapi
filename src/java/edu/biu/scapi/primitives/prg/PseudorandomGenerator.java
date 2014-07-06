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


package edu.biu.scapi.primitives.prg;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.SecretKey;

/** 
 * General interface of pseudorandom generator. Every concrete class in this family should implement this interface. <p>
 * 
 * A pseudorandom generator (PRG) is a deterministic algorithm that takes a “short” uniformly distributed string, 
 * known as the seed, and outputs a longer string that cannot be efficiently distinguished from a uniformly 
 * distributed string of that length.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
  */
public interface PseudorandomGenerator {
	
	/**
	 * Sets the secret key for this prg.
	 * The key can be changed at any time. 
	 * @param secretKey secret key
	 * @throws InvalidKeyException 
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException;
	
	/**
	 * An object trying to use an instance of prg needs to check if it has already been initialized with a key.
	 * @return true if the object was initialized by calling the function setKey.
	 */
	public boolean isKeySet();

	/** 
	 * @return the algorithm name. For example - RC4
	 */
	public String getAlgorithmName();
	
	/**
	 * Generates a secret key to initialize this prg object.
	 * @param keyParams algorithmParameterSpec contains the required parameters for the key generation
	 * @return the generated secret key
	 * @throws InvalidParameterSpecException 
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException;
	
	/**
	 * Generates a secret key to initialize this prg object.
	 * @param keySize is the required secret key size in bits 
	 * @return the generated secret key 
	 */
	public SecretKey generateKey(int keySize);

	/**
	 * Streams the prg bytes.
	 * @param outBytes - output bytes. The result of streaming the bytes.
	 * @param outOffset - output offset
	 * @param outlen - the required output length
	 */
	public void getPRGBytes(byte[] outBytes, int outOffset, int outlen) ;
	
	

	
}
