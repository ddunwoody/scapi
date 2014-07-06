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

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.NoMaxException;
import edu.biu.scapi.primitives.prf.PseudorandomFunction;
import edu.biu.scapi.primitives.prf.bc.BcAES;
import edu.biu.scapi.tools.Factories.PrfFactory;

/**
 * This is a simple way of generating a pseudorandom stream from a pseudorandom function. The seed for the pseudorandom generator is the key to the pseudorandom function. 
 * Then, the algorithm initializes a counter to 1 and applies the pseudorandom function to the counter, increments it, and repeats.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ScPrgFromPrf implements PseudorandomGenerator{

	private PseudorandomFunction prf;	// Underlying PRF.
	private byte[] ctr;					//Counter used for key generation.
	private boolean isKeySet;

	/**
	 * Default constructor. Uses default implementation PRF.
	 */
	public ScPrgFromPrf(){
		prf = new BcAES();
	}

	/**
	 * Constructor that lets the user choose the underlying PRF algorithm.
	 * @param prf underlying PseudorandomFunction.
	 */
	public ScPrgFromPrf(PseudorandomFunction prf){
		this.prf = prf;
	}

	/**
	 * Constructor that lets the user choose the underlying PRF algorithm.
	 * @param prfName PseudorandomFunction algorithm name.
	 */
	public ScPrgFromPrf(String prfName) throws FactoriesException{
		this(PrfFactory.getInstance().getObject(prfName));
	}

	/**
	 * Initializes this PRG with SecretKey.
	 * @param secretKey suitable for the given Prf
	 * @throws InvalidKeyException 
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException {
		prf.setKey(secretKey); //Sets the key to the underlying prf.
		//Creates the counter. It should be the same size as the prf's block size.
		//If there is no limit on the block size, use default size.
		try {
			ctr = new byte[prf.getBlockSize()];
		} catch (NoMaxException e){
			ctr = new byte[16];
		}

		//Initializes the counter to 1.
		ctr[ctr.length-1] = 1;
		isKeySet = true;

	}

	@Override
	public boolean isKeySet() {
		return isKeySet;
	}

	/** 
	 * Returns the name of the algorithm - PRG with {name of the underlying prf}.
	 * @return - the algorithm name.
	 */
	@Override
	public String getAlgorithmName() {

		return "PRG_from_" + prf.getAlgorithmName();
	}

	/**
	 * Generates a secret key to initialize this prg object.
	 * @param keyParams should be an instance of PrgFromPrfParameterSpec
	 * @return the generated secret key
	 * @throws InvalidParameterSpecException if the given params is not an instance of PrgFromPrfParameterSpec
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		return prf.generateKey(keyParams);
	}

	/**
	 * This function is not supported in this implementation. Throws exception.
	 * @throws UnsupportedOperationException 
	 */
	public SecretKey generateKey(int keySize) {
		return prf.generateKey(keySize);
	}

	/**
	 * Generates pseudorandom bytes using the underlying prf.
	 * @param outBytes - output bytes. The result of streaming the bytes.
	 * @param outOffset - output offset
	 * @param outLen - the required output length.
	 * @throws IllegalStateException if no key was set.
	 * @throws ArrayIndexOutOfBoundsException if the given offset or length is invalid.
	 */
	@Override
	public void getPRGBytes(byte[] outBytes, int outOffset, int outLen) {
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//checks that the offset and the length are correct
		if ((outOffset > outBytes.length) || ((outOffset + outLen) > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}

		int numGeneratedBytes = 0;	//Number of current generated bytes.
		byte [] generatedBytes = new byte[ctr.length];

		while(numGeneratedBytes < outLen){
			try {
				//If the prf can output any length (for example, IteratedPrfVarying) call the computeBlock with the outputLen.
				prf.computeBlock(ctr, 0, ctr.length, outBytes, outOffset + numGeneratedBytes, outLen);
				numGeneratedBytes += outLen;
			} catch (IllegalBlockSizeException e) {
				try {
					//If the prf can receive any input length (for example, Hmac) call the computeBlock with the ctr length.
					//The output is written to a new array because there is no guarantee that output array is long enough to hold the next output block.
					prf.computeBlock(ctr, 0, ctr.length, generatedBytes, 0);
					//Copy the right number of generated bytes.
					if (numGeneratedBytes + generatedBytes.length <= outLen){
						System.arraycopy(generatedBytes, 0, outBytes, outOffset + numGeneratedBytes, generatedBytes.length);
					} else {
						System.arraycopy(generatedBytes, 0, outBytes, outOffset + numGeneratedBytes, outLen - numGeneratedBytes);
					}
					//Increases the number of generated bytes.
					numGeneratedBytes += ctr.length;
				} catch (IllegalBlockSizeException e1) {
					try {
						//If the prf can receive fixed input length (for example, AES) call the computeBlock without the input length.
						//The output is written to a new array because there is no guarantee that output array is long enough to hold the next output block.
						prf.computeBlock(ctr, 0, generatedBytes, 0);
						//Copy the right number of generated bytes.
						if (numGeneratedBytes + generatedBytes.length <= outLen){
							System.arraycopy(generatedBytes, 0, outBytes, outOffset + numGeneratedBytes, generatedBytes.length);
						} else {
							System.arraycopy(generatedBytes, 0, outBytes, outOffset + numGeneratedBytes, outLen - numGeneratedBytes);
						}
						//Increases the number of generated bytes.
						numGeneratedBytes += ctr.length;
					} catch (IllegalBlockSizeException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					}
				}
			}
			//Increases the counter.
			increaseCtr();
		}

	}

	/**
	 * Increases the ctr byte array by 1 bit.
	 */
	private void increaseCtr(){

		//increase the counter by one.
		int    carry = 1;
		int len = ctr.length;

		for (int i = len - 1; i >= 0; i--)
		{
			int    x = (ctr[i] & 0xff) + carry;

			if (x > 0xff)
			{
				carry = 1;
			}
			else
			{
				carry = 0;
			}

			ctr[i] = (byte)x;
		}
	} 


}
