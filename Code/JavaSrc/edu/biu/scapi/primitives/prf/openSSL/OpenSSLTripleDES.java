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

import edu.biu.scapi.primitives.prf.TripleDES;

/**
 * Concrete class of PRF family for Triple DES. This class wraps the implementation of OpenSSL library.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OpenSSLTripleDES extends OpenSSLPRP implements TripleDES{
	
	//Native functions that implements TripleDES using OpenSSL functions.
	private native long createTripleDESCompute();	//Creates TripleDES object that compute the function on a block.
	private native long createTripleDESInvert();	//Creates TripleDES object that invert the function on a block.
	private native void setKey(long computeP, long invertP, byte[] key); //Sets a key to the native TripleDES objects.
	
	/**
	 * Default constructor that creates the TripleDES objects. Uses default implementation of SecureRandom.
	 */
	public OpenSSLTripleDES(){
		this(new SecureRandom());
	}
	
	/**
	 * Constructor that creates the TripleDES objects and lets the user choose the source of randomness to use.
	 * @param random source of randomness.
	 */
	public OpenSSLTripleDES(SecureRandom random){
		super(random);
		
		//Create the native objects.
		computeP = createTripleDESCompute();
		invertP = createTripleDESInvert();
	}
	
	/**
	 * Constructor that creates the TripleDES objects and lets the user choose the random algorithm to use.
	 * @param randNumGenAlg random number generator algorithm.
	 * @throws NoSuchAlgorithmException if the given algorithm is not valid.
	 */
	public OpenSSLTripleDES(String randNumGenAlg) throws NoSuchAlgorithmException{
		this(SecureRandom.getInstance(randNumGenAlg));
	}

	/** 
	 * Initializes this TripleDES objects with the given secret key.
	 * @param secretKey secret key.
	 * @throws InvalidKeyException if the key is not 128/192 bits long.
	 */
	@Override
	public void setKey(SecretKey secretKey) throws InvalidKeyException {
		int len = secretKey.getEncoded().length;
		//TripleDES key size should be 128/192 bits long
		if(len!=16 && len!=24){
			throw new InvalidKeyException("TripleDES key size should be 128/192 bits long");
		}
		
		//Set the key to the native objects.
		setKey(computeP, invertP, secretKey.getEncoded());
		
		isKeySet = true;
	}

	@Override
	public String getAlgorithmName() {
		return "TripleDES";
	}

	@Override
	public int getBlockSize(){
		//TripleDES works on 64 bit block.
		return 8;
	}
	
	static {
		//loads the OpenSSL dll.
		 System.loadLibrary("OpenSSLJavaInterface");
	}
}
