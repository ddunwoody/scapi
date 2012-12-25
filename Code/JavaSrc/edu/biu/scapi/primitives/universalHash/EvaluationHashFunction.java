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


package edu.biu.scapi.primitives.universalHash;

import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.paddings.BitPadding;
import edu.biu.scapi.paddings.NoPadding;
import edu.biu.scapi.paddings.PaddingScheme;
import edu.biu.scapi.tools.Factories.PaddingFactory;

/** 
 * Concrete class of perfect universal hash for evaluation hash function.
 * 
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class EvaluationHashFunction implements UniversalHash{
	private SecureRandom random;
	protected SecretKey secretKey = null;
	protected boolean isKeySet = false;
	
	protected long evalHashPtr; // pointer to the native evaluation object
	private PaddingScheme padding;
	
	//native functions. These functions are implemented in the NTLJavaInterface dll using the JNI
	
	//creates the native object and initializes it with the secret key
	private native long initHash(byte[] key, long keyOffset);
	//computes the evaluation hash function
	//we don't send the input offset because we always send the padded array which the offset is always 0 
	private native void computeFunction(long evalHashPtr, byte[] in, byte[] out, int outOffset);
	
	/**
	 * Default constructor. uses Bit padding.
	 */
	public EvaluationHashFunction(){
		this(new BitPadding(), new SecureRandom());
	}
	
	/**
	 * Constructor that receives the names of the required padding scheme and randomness algorithm.
	 * @param paddingName - name of padding scheme to use.
	 * @param randNumGenAlg name of random algorithm to use.
	 * @throws FactoriesException
	 * @throws NoSuchAlgorithmException 
	 */
	public EvaluationHashFunction(String paddingName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException{
		//creates padding scheme and random, then call the other constructor
		this(PaddingFactory.getInstance().getObject(paddingName), SecureRandom.getInstance(randNumGenAlg));
	}
	
	/**
	 * Constructor that receives the padding scheme and random to use.
	 * @param padding
	 * @param random
	 */
	public EvaluationHashFunction(PaddingScheme padding, SecureRandom random){
		this.padding = padding;
		this.random = random;
	}
	
	public void setKey(SecretKey secretKey) {

		//passes the key to the native function, which creates a native evaluation hash function instance.
		//the return value is the pointer to this instance, which we set to the class member evalHashPtr
		evalHashPtr = initHash(secretKey.getEncoded(), 0);
		
		//sets the key
		this.secretKey = secretKey;
		
		isKeySet = true; //marks this object as initialized
	}
	
	public boolean isKeySet() {
		return isKeySet; 
	}
	
	/**
	 * Evaluation hash function can get any input size which is between 0 to 64t bits. while t = 2^24.
	 * @return the upper bound of the input size - 64t
	 */
	public int getInputSize() {
		//limit = t = 2^24
		int limit = (int) Math.pow(2, 24);
		//limit = 8t, which is 64t bits in bytes
		limit = limit * 8;
		//save maximum 8 byte to the padding
		limit = limit - 8;
		return limit;
	}

	/** 
	 * @return the output size of evaluation hash function - 8 bytes.
	 */
	public int getOutputSize() {
		
		//64 bits long
		return 8;
	}

	/**
	 * @return the algorithm name - Evaluation Hash Function
	 */
	public String getAlgorithmName() {
		
		return "Evaluation Hash Function";
	}

	/**
	 * Generates a secret key to initialize this UH object.
	 * @param keyParams algorithmParameterSpec contains the required secret key size in bits 
	 * @return the generated secret key
	 * @throws InvalidParameterSpecException 
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException{
		throw new UnsupportedOperationException("To generate a key for this univarsal hash object use the generateKey(int keySize) function");
	}
	
	/**
	 * Generates a secret key to initialize this UH object.
	 * @param keySize is the required secret key size in bits (it has to be greater than 0 a multiple of 8) 
	 * @return the generated secret key 
	 */
	public SecretKey generateKey(int keySize){
		//generate a random string of bits of length keySize, which has to be greater than zero. 
		
		//if the key size is zero or less - throw exception
		if (keySize <= 0){
			throw new NegativeArraySizeException("Key size must be greater than 0");
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
	
	public void compute(byte[] in, int inOffset, int inLen, byte[] out,
			int outOffset) throws IllegalBlockSizeException {
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//checks that the offset and length are correct
		if ((inOffset > in.length) || (inOffset+inLen> in.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOffset > out.length) || (outOffset+getOutputSize() > out.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		
		//checks that the input length is not greater than the upper limit
		if(inLen > getInputSize()){
			throw new IllegalBlockSizeException("input length must be less than 64*(2^24-1) bits long");
		}
		
		byte[] paddedArray = null;
		//pad the input.
		if ((inLen%8) == 0){
			//the input is aligned to 64 bits so pads it as aligned array
			paddedArray = pad(in, inOffset, inLen, 8);
		} else {
			if (padding instanceof NoPadding){
				throw new IllegalArgumentException("input is not aligned to blockSize");
			}
			//gets the number of bytes to add in order to get an aligned array
			int inputSizeMod8 = inLen % 8;
			int leftToAlign = 8 - inputSizeMod8;
			//the input is not aligned to 64 bits so pads it to aligned array
			paddedArray = pad(in, inOffset, inLen, leftToAlign);
		}
		
		//calls the native function compute on the padded array.
		computeFunction(evalHashPtr, paddedArray, out, outOffset);
	}
	
	/**
	 * This padding is used to get an array aligned to 8 bytes (64 bits).
	 * The padding is done by calling the padding scheme class member to pad the array.
	 * The input for this function is an array of size that is not aligned to 8 bytes.
	 * @param input the input to pad. 
	 * @param offset the offset to take the input bytes from
	 * @param length the length of the input. This length is not aligned to 8 bytes.
	 * @return the aligned array
	 */
	private byte[] pad(byte[] input, int offset, int length, int padSize){

		//copy the relevant part of the array to a new one
		byte[] inputToPad = new byte[length];
		System.arraycopy(input, offset, inputToPad, 0, length);
		
		//call the padding scheme to pad the array
		return padding.pad(inputToPad, padSize);
	}
	
	
	static {
		 
		 //load the NTL jni dll
		 System.loadLibrary("NTLJavaInterface");
	}
}
