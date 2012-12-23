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


package edu.biu.scapi.primitives.prf;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

/** 
 * This class implements some common functionality of varying input and output length prf classes.
 * 
 * PrfVaryingFromPrfVaryingInput is a pseudorandom function with varying input/output lengths, based on HMAC or any other implementation 
 * of PrfVaryingInputLength. We take the interpretation that there is essentially a different random function for every output length. 
 * This can be modeled by applying the random function to the input and the required output length (given as input to the oracle). 
 * The pseudorandom function must then be indistinguishable from this.
 * We use PrfVaryingInputLength for this construction because the input length can already be varying; this makes the construction more simple and efficient. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 * 
 */
public abstract class PrfVaryingFromPrfVaryingInput implements PrfVaryingIOLength {
	
	protected PrfVaryingInputLength prfVaryingInputLength; //the underlying prf varying input
	
	
	/** 
	 * Initializes this PrfVaryingFromPrfVaryingInput with the secret key.
	 * @param secretKey secret key
	 * @throws InvalidKeyException 
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException {

		prfVaryingInputLength.setKey(secretKey); //initializes the underlying prf
		
	}

	/**
	 * Check that the Secret Key for this instance has been set
	 * @return true if key had been set<p>
	 * 			false, otherwise.
	 */
	public boolean isKeySet(){
		return prfVaryingInputLength.isKeySet();
	}
	

	/** 
	 * Since both input and output variables are varying this function should not be called.
	 * @throws UnsupportedOperationException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws IllegalBlockSizeException{
		throw new UnsupportedOperationException("Only compute that gets lengths of I/O should be called for Varying Prf");
	}



	/** 
	 * Since both input and output variables are varying this function should not be call.
	 * @throws UnsupportedOperationException
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen,
			byte[] outBytes, int outOff) throws IllegalBlockSizeException{
		throw new UnsupportedOperationException("Only compute that gets lengths of I/O should be called for Varying Prf");
	}
	
	/**
	 * Generate a SecretKey suitable for a Pseudo random permutation obtained from a Varying Prf.
	 * @param keyParams an instance of a class implementing the AlgorithmParameterSpec interface 
	 * 					that holds the necessary parameters to generate the key.
	 * @return the generated secret key
	 * @throws InvalidParameterSpecException if keyParams is not an instance of relevant Parameter Spec.
	 */
	@Override
	public SecretKey generateKey(AlgorithmParameterSpec keyParams)
			throws InvalidParameterSpecException {
		return prfVaryingInputLength.generateKey(keyParams);
	}

	/**
	 * Generate a SecretKey suitable for a Pseudo random permutation obtained from a Varying Prf.
	 * @param keySize bit-length of required Secret Key
	 * @return the generated secret key
	 */
	@Override
	public SecretKey generateKey(int keySize) {
		return prfVaryingInputLength.generateKey(keySize);
	}

}
