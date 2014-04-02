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
package edu.biu.scapi.primitives.prf.openSSL;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import edu.biu.scapi.primitives.prf.AES;

/**
 * Concrete class of PRF family for AES. This class wraps the implementation of OpenSSL library.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OpenSSLAES extends OpenSSLPRP implements AES{
	//Native functions that implements AES using OpenSSL functions.
	private native long createAESCompute();	//Creates AES object that compute the AES function on a block.
	private native long createAESInvert();	//Creates AES object that invert the AES function on a block.
	private native void setKey(long computeP, long invertP, byte[] key); //Sets a key to the native AES objects.
	
	/**
	 * Default constructor that creates the AES objects. Uses default implementation of SecureRandom.
	 */
	public OpenSSLAES(){
		this(new SecureRandom());
	}
	
	/**
	 * Constructor that creates the AES objects and lets the user choose the source of randomness to use.
	 * @param random source of randomness.
	 */
	public OpenSSLAES(SecureRandom random){
		super(random);
		
		//Create the native AES objects.
		computeP = createAESCompute();
		invertP = createAESInvert();
	}
	
	/**
	 * Constructor that creates the AES objects and lets the user choose the random algorithm to use.
	 * @param randNumGenAlg random number generator algorithm.
	 * @throws NoSuchAlgorithmException if the given algorithm is not valid.
	 */
	public OpenSSLAES(String randNumGenAlg) throws NoSuchAlgorithmException{
		this(SecureRandom.getInstance(randNumGenAlg));
	}

	/** 
	 * Initializes this AES objects with the given secret key.
	 * @param secretKey secret key.
	 * @throws InvalidKeyException if the key is not 128/192/256 bits long.
	 */
	@Override
	public void setKey(SecretKey secretKey) throws InvalidKeyException {
		int len = secretKey.getEncoded().length;
		//AES key size should be 128/192/256 bits long.
		if(len!=16 && len!=24 && len!=32){
			throw new InvalidKeyException("AES key size should be 128/192/256 bits long");
		}
		
		//Set the key to the native objects.
		setKey(computeP, invertP, secretKey.getEncoded());
		
		isKeySet = true;
	}

	@Override
	public String getAlgorithmName() {
		return "AES";
	}

	@Override
	public int getBlockSize(){
		//AES works on 128 bit block.
		return 16;
	}
	
	/**
	 * Deletes the native AES objects.
	 */
	protected void finalize() throws Throwable {

		super.finalize();
	}
	
	static {
		//loads the OpenSSL dll.
		 System.loadLibrary("OpenSSLJavaInterface");
	}
}
