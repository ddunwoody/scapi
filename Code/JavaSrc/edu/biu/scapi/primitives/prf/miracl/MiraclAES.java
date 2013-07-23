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
package edu.biu.scapi.primitives.prf.miracl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import edu.biu.scapi.primitives.prf.AES;

public class MiraclAES implements AES{

	private boolean isKeySet;
	private long aes;				//native object used for compute AES permutation
	private SecureRandom random;
	
	private native long createAES(byte[] key);
	private native void computeBlock(long aes, byte[] in, int inOffset, byte[] out, int outOffset);
	private native void invertBlock(long aes, byte[] in, int inOffset, byte[] out, int outOffset);
	private native void optimizedCompute(long aes, byte[] in, byte[] out);
	private native void optimizedInvert(long aes, byte[] in, byte[] out);
	private native void deleteAES(long aes);
	
	/**
	 * Default constructor. Uses default implementation of SecureRandom.
	 */
	public MiraclAES(){
		//Call the general constructor with new SecureRandom object.
		this(new SecureRandom());
	}
	
	/**
	 * Constructor that lets the user choose the source of randomness to use.
	 * @param random source of randomness.
	 */
	public MiraclAES(SecureRandom random){
		
		this.random = random; //Sets the given random
	}
	
	/**
	 * Constructor that lets the user choose the random algorithm to use.
	 * @param randNumGenAlg random number generator algorithm.
	 * @throws NoSuchAlgorithmException if the given algorithm is not valid.
	 */
	public MiraclAES(String randNumGenAlg) throws NoSuchAlgorithmException{
		//Create the SecureRandom object and call the general constructor with it.
		this(SecureRandom.getInstance(randNumGenAlg));
	}

	/** 
	 * Initializes this AES object with the given secret key.
	 * @param secretKey secret key
	 * @throws InvalidKeyException 
	 */
	@Override
	public void setKey(SecretKey secretKey) throws InvalidKeyException {
		int len = secretKey.getEncoded().length;
		//AES key size should be 128/192/256 bits long
		if(len!=16 && len!=24 && len!=32){
			throw new InvalidKeyException("AES key size should be 128/192/256 bits long");
		}
		//Creates the native object that computes the AES permutation and sets the key.
		aes = createAES(secretKey.getEncoded());

		isKeySet = true;
	}

	@Override
	public boolean isKeySet() {
		return isKeySet;
	}

	@Override
	public String getAlgorithmName() {
		return "MiraclAES";
	}

	@Override
	public int getBlockSize(){
		//We defined Miracl AES to work in MR_CBC mode. This mode work on 16 bytes block size.
		return 16;
	}

	/**
	 * This function should not be used to generate a key for AES and it throws UnsupportedOperationException.
	 * @throws UnsupportedOperationException 
	 */
	@Override
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		throw new UnsupportedOperationException("To generate a key for this prf object use the generateKey(int keySize) function");
	}

	/**
	 * Generates a secret key to initialize this AES object.
	 * @param keySize is the required secret key size in bits.
	 * @return the generated secret key.
	 */
	@Override
	public SecretKey generateKey(int keySize) {
		SecretKey secretKey = null;
		//Looks for a default provider implementation of the key generation for AES. 
		try {
			//gets the KeyGenerator of this algorithm
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			//if the key size is zero or less - uses the default key size as implemented in the provider implementation
			if(keySize <= 0){
				keyGen.init(random);
			//else, uses the keySize to generate the key
			} else {
				keyGen.init(keySize, random);
			}
			//generates the key
			secretKey = keyGen.generateKey();
		
		//Could not find a default provider implementation.
		} catch (NoSuchAlgorithmException e) {
			//shouldn't occur since the AES has key generator that implemented by sun.
		}
		
		return secretKey;
	}

	/** 
	 * Computes the AES permutation on the given block. <p>
	 * 
	 * @param inBytes input bytes to compute.
	 * @param inOff input offset in the inBytes array.
	 * @param outBytes output bytes. The resulted bytes of compute.
	 * @param outOff output offset in the outBytes array to put the result from.
	 */
	@Override
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff) {
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		// Checks that the offset and length are correct.
		if ((inOff > inBytes.length) || (inOff+getBlockSize() > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		
		//Call the native code to perform computeBlock
		computeBlock(aes, inBytes, inOff, outBytes, outOff);
	}
	
	/** 
	 * Computes the AES permutation on the given array. 
	 * The given array length does not have to be the size of the block but a MUST be aligned to the block size.
	 * The optimized compute block divide the given input into blocks and compute each one of them separately. 
	 * The output array will contain a concatenation of all the results of computing the blocks. 
	 * 
	 * @param inBytes input bytes to compute.
	 * @param outBytes output bytes. The resulted bytes of compute.
	 * @throws IllegalArgumentException if the given input is not aligned to block size.
	 * @throws IllegalArgumentException if the given input and output are not in the same size.
	 */
	public void optimizedCompute(byte[] inBytes, byte[] outBytes) {
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		if ((inBytes.length % getBlockSize()) != 0){
			throw new IllegalArgumentException("inBytes should be aligned to the block size");
		}
		
		if (outBytes.length != inBytes.length){
			throw new IllegalArgumentException("outBytes and inBytes must be in the same size");
		}
			
		optimizedCompute(aes, inBytes, outBytes);
	}

	/** 
	 * This function is provided in the interface especially for the sub-family PrfVaryingIOLength, which may have variable input/output lengths.
	 * Since both Input and output variables are fixed this function should not normally be called. 
	 * If the user still wants to use this function, the input and output lengths should be the same as 
	 * the result of <code>getBlockSize</code>, otherwise, throws an exception.
	 * @param inBytes input bytes to compute.
	 * @param inOff input offset in the inBytes array.
	 * @param outBytes output bytes. The resulted bytes of compute.
	 * @param outOff output offset in the outBytes array to put the result from.
	 * @throws IllegalBlockSizeException 
	 */
	@Override
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen)
			throws IllegalBlockSizeException {
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//The checks on the offset and length are done in the computeBlock(inBytes, inOff, outBytes, outOff).
		if (inLen==outLen && inLen==getBlockSize()) //Checks that the lengths are the same as the block size.
			computeBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("Wrong size");			
		
	}

	/**
	 * This function is provided in the interface especially for the sub-family PrfVaryingInputLength, which may have variable input length.
	 * Since this is a prp, the input length is fixed with the block size, so this function normally shouldn't be called. 
	 * If the user still wants to use this function, the input length should be the same as the block size. Otherwise, throws an exception.
	 * 
	 * @param inBytes input bytes to compute.
	 * @param inLen the length of the input array.
	 * @param inOffset input offset in the inBytes array.
	 * @param outBytes output bytes. The resulted bytes of invert.
	 * @param outOffset output offset in the outBytes array to put the result from.
	 */

	@Override
	public void computeBlock(byte[] inBytes, int inOffset, int inLen, byte[] outBytes, int outOffset)
			 throws IllegalBlockSizeException {
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//The checks on the offset and length is done in the computeBlock (inBytes, inOffset, outBytes, outOffset).
		if(inLen==getBlockSize()) //Checks that the input length is the same as the block size.
			computeBlock(inBytes, inOffset, outBytes, outOffset);
		else
			throw new IllegalBlockSizeException("Wrong size");
		
	}
	
	/** 
	 * Inverts the AES permutation on the given block.
	 * 
	 * @param inBytes input bytes to compute.
	 * @param inOff input offset in the inBytes array.
	 * @param outBytes output bytes. The resulted bytes of invert.
	 * @param outOff output offset in the outBytes array to put the result from.
	 */
	@Override
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff){
		
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		// Checks that the offsets are correct 
		if ((inOff > inBytes.length) || (inOff+getBlockSize() > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		
		//Call the native code to perform invert
		invertBlock(aes, inBytes, inOff, outBytes, outOff);	
	}
	
	/**
	 * Inverts the AES permutation on the given array. 
	 * The given array length does not have to be the size of the block but a MUST be aligned to the block size.
	 * The optimized invert block divides the given input into blocks and inverts each one of them separately. 
	 * The output array will contain a concatenation of all the results of inverting the blocks. 
	 * 
	 * @param inBytes input bytes to invert.
	 * @param outBytes output bytes. The inverted bytes. 
	 * @throws IllegalArgumentException if the given input is not aligned to block size.
	 * @throws IllegalArgumentException if the given input and output are not in the same size.
	 */
	public void optimizedInvert(byte[] inBytes, byte[] outBytes ){
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		
		if ((inBytes.length % getBlockSize()) != 0){
			throw new IllegalArgumentException("inBytes should be aligned to the block size");
		}
		
		if (outBytes.length != inBytes.length){
			throw new IllegalArgumentException("outBytes and inBytes must be in the same size");
		}
		
		//Call the native code to perform invert
		optimizedInvert(aes, inBytes, outBytes);	
	}

	/**
	 * This function is provided in the interface especially for the sub-family PrpVarying, which may have variable input/output lengths.
	 * Since in this case, both input and output variables are fixed this function should not normally be called. 
	 * If the user still wants to use this function, the specified argument <code>len</code> should be the same as 
	 * the result of <code>getBlockSize</code>, otherwise, throws an exception. 
	 * @param inBytes input bytes to invert.
	 * @param inOff input offset in the inBytes array.
	 * @param outBytes output bytes. The resulted bytes of invert.
	 * @param outOff output offset in the outBytes array to put the result from.
	 * @param len the length of the input and the output.
	 * @throws IllegalBlockSizeException.
	 */
	@Override
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,	int outOff, int len) throws IllegalBlockSizeException {
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//The checks of the offset and lengths are done in the invertBlock(inBytes, inOff, outBytes, outOff)
		if (len==getBlockSize()) //Checks that the length is the same as the block size
			invertBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("Wrong size");
		
	}
	
	/**
	 * deletes the related Dlog group object
	 */
	protected void finalize() throws Throwable {

		// delete from the dll the dynamic allocation of AES pointer.
		deleteAES(aes);

		super.finalize();
	}
	
	//Load the miracl dll.
	static {
        System.loadLibrary("MiraclJavaInterface");
	}
}
