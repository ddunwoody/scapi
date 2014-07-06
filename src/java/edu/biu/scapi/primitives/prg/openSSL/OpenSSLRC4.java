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
package edu.biu.scapi.primitives.prg.openSSL;

import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.primitives.prg.RC4;

/**
 * This class wraps the OpenSSL implementation of RC4.
 * 
 * RC4 is a well known stream cipher, that is essentially a pseudorandom generator.<p> 
 * In our implementation, we throw out the first 1024 bits since the first few bytes have been shown to have some bias. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class OpenSSLRC4 implements RC4{
	
	private long rc4; //pointer to the native RC4 object.
	
	private SecureRandom random;
	private boolean isKeySet;
	
	//Native functions that uses OpenSSL's RC4 implementation. 
	private native long createRC4();						// Creates the native RC4 object.
	private native void initRC4(long rc4, byte[] key);		// Initializes the native RC4 with the key.
	private native void generateBytes(long rc4, int outLen, byte[] outBytes, int outOffset); //Generates RC4's bytes.
	private native void deleteNative(long rc4);				//Deleted the native object.
	
	/**
	 * Creates the object using default random.
	 */
	public OpenSSLRC4(){
		this (new SecureRandom());
	}
	
	/**
	 * Creates the object using the given random object.
	 * @param random
	 */
	public OpenSSLRC4(SecureRandom random){
		this.random = random;
		
		//Creates the native object.
		rc4 = createRC4();
	}
	
	/**
	 * Creates the object using the given random number generator algorithm.
	 * @param randNumGenAlg
	 * @throws NoSuchAlgorithmException if the given algorithm is not exist.
	 */
	public OpenSSLRC4(String randNumGenAlg) throws NoSuchAlgorithmException {
		
		this(SecureRandom.getInstance(randNumGenAlg));
	}
	
	/**
	 * Sets the given key.
	 */
	public void setKey(SecretKey secretKey) {
		//Call the native function to set the key.
		initRC4(rc4, secretKey.getEncoded());
		//Marks this object as initialized.
		isKeySet = true;
		
		//RC4 has a problem in the first 1024 bits. by ignoring these bytes, we bypass this problem.
		byte[] out = new byte[128];
		getPRGBytes(out, 0, 128);
		
	}
	
	public boolean isKeySet(){
		return isKeySet;
	}
	
	/** 
	 * Returns the name of the algorithm.
	 * @return - the algorithm name "RC4".
	 */
	public String getAlgorithmName() {
		
		return "RC4";
	}

	/**
	 * This function is not supported in this implementation. Throws exception.
	 * @throws UnsupportedOperationException 
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException{
		throw new UnsupportedOperationException("To generate a key for this prg object use the generateKey(int keySize) function");
	}
	
	/**
	 * Generates a secret key to initialize this prg object.
	 * @param keySize is the required secret key size in bits (it has to be greater than 0 a multiple of 8).
	 * @return the generated secret key 
	 */
	public SecretKey generateKey(int keySize){
		//Generate a random string of bits of length keySize, which has to be greater that zero. 

		//If the key size is zero or less - throw exception
		if (keySize <= 0){
			throw new NegativeArraySizeException("key size must be greater than 0");
		}
		//The key size has to be a multiple of 8 so that we can obtain an array of random bytes which we use
		//to create the SecretKey.
		if ((keySize % 8) != 0)  {
			throw new InvalidParameterException("Wrong key size: must be a multiple of 8");
		}
		//Creates a byte array of size keySize.
		byte[] genBytes = new byte[keySize/8];

		//Generates the bytes using the random.
		random.nextBytes(genBytes);
		//Creates a secretKey from the generated bytes.
		SecretKey generatedKey = new SecretKeySpec(genBytes, "");
		return generatedKey;
		
	}
	
	/** 
	 * Streams the bytes using the underlying stream cipher.
	 * @param outBytes - output bytes. The result of streaming the bytes.
	 * @param outOffset - output offset.
	 * @param outLen - the required output length.
	 */
	public void getPRGBytes(byte[] outBytes, int outOffset,	int outLen){
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//checks that the offset and the length are correct.
		if ((outOffset > outBytes.length) || ((outOffset + outLen) > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		
		//out array will be filled with pseudorandom bytes (that were xored with zeroes in the in array).
		generateBytes(rc4, outLen, outBytes, outOffset);
	}
	
	/**
	 * deletes the native RC4 object.
	 */
	protected void finalize() throws Throwable {

		// delete from the dll the dynamic allocation.
		deleteNative(rc4);
	}
	
	static {
		//loads the OpenSSL dll.
		 System.loadLibrary("OpenSSLJavaInterface");
	}
}
