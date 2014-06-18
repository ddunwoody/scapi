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


package edu.biu.scapi.primitives.prg.bc;

import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;

import edu.biu.scapi.primitives.prg.PseudorandomGenerator;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;

/**
 * A general adapter class of PRG for bouncy castle. <p>
 * This class implements the PRG functionality by passing requests to the adaptee interface StreamCipher.
 * A concrete prg such as RC4 represented in the class BcRC4 only passes the RC4Engine object in the constructor.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public abstract class BcPRG implements PseudorandomGenerator {
	
	private SecureRandom random;
	private boolean isKeySet = false;
	private StreamCipher bcStreamCipher;	//the underlying stream cipher of bc
	private CipherParameters bcParams;		//the parameters for the underlying StreamCipher
		

	/** 
	 * Sets the StreamCipher of bc to adapt to.
	 * @param bcStreamCipher - the concrete StreamCipher of bc
	 */
	public BcPRG(StreamCipher bcStreamCipher) {
		//creates a random and call the other constructor
		this(bcStreamCipher, new SecureRandom());
	}
	
	/** 
	 * Sets the StreamCipher of bc to adapt to and the secureRandom object.
	 * @param bcStreamCipher - the concrete StreamCipher of bc
	 * @param random
	 */
	public BcPRG(StreamCipher bcStreamCipher, SecureRandom random) {
		this.bcStreamCipher = bcStreamCipher;
		this.random = random;
	}
	
	public void setKey(SecretKey secretKey) {
		
		//gets the BC keyParameter relevant to the secretKey
		bcParams = BCParametersTranslator.getInstance().translateParameter(secretKey);
		
		//initializes the underlying stream cipher. Note that the first argument is irrelevant and thus does not matter is true or false.
		bcStreamCipher.init(false, bcParams);
		
		//marks this object as initialized
		isKeySet = true;
	}
	
	public boolean isKeySet(){
		return isKeySet;
	}
	
	/** 
	 * Returns the name of the algorithm through the underlying StreamCipher
	 * @return - the algorithm name
	 */
	public String getAlgorithmName() {
		
		return bcStreamCipher.getAlgorithmName();
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
	 * @param keySize is the required secret key size in bits (it has to be greater than 0 a multiple of 8)
	 * @return the generated secret key 
	 */
	public SecretKey generateKey(int keySize){
		//generate a random string of bits of length keySize, which has to be greater that zero. 

		//if the key size is zero or less - throw exception
		if (keySize <= 0){
			throw new NegativeArraySizeException("key size must be greater than 0");
		}
		//the key size has to be a multiple of 8 so that we can obtain an array of random bytes which we use
		//to create the SecretKey.
		if ((keySize % 8) != 0)  {
			throw new InvalidParameterException("Wrong key size: must be a multiple of 8");
		}
		//creates a byte array of size keySize
		byte[] genBytes = new byte[keySize/8];

		//generates the bytes using the random
		random.nextBytes(genBytes);
		//creates a secretKey from the generated bytes
		SecretKey generatedKey = new SecretKeySpec(genBytes, "");
		return generatedKey;
		
	}
	
	/** 
	 * Streams the bytes using the underlying stream cipher.
	 * @param outBytes - output bytes. The result of streaming the bytes.
	 * @param outOffset - output offset
	 * @param outLen - the required output length
	 * @throws UnInitializedException if this object is not initialized
	 */
	public void getPRGBytes(byte[] outBytes, int outOffset,	int outLen){
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//checks that the offset and the length are correct
		if ((outOffset > outBytes.length) || ((outOffset + outLen) > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		
		/*
		 * BC generates bytes and does XOR between them to the given byte array. 
		 * In order to get the bytes without XOR we send a zeroes array to be XOR-ed with the generated bytes.
		 * Because XOR with zeroes returns the input to the XOR - we will get the generated bytes.
		 */
		
		//in array filled with zeroes
		byte[] inBytes = new byte[outLen];
		
		//out array filled with pseudorandom bytes (that were xored with zeroes in the in array)
		bcStreamCipher.processBytes(inBytes, 0, outLen, outBytes, outOffset);
	}


}
