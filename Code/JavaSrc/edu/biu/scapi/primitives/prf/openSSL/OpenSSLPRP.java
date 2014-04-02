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

import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.primitives.prf.PrpFixed;

public abstract class OpenSSLPRP implements PrpFixed{
	protected long computeP;	//Native object used to compute the prp.
	protected long invertP;		//Native object used to invert the prp.
	
	protected boolean isKeySet; 
	private SecureRandom random;
	
	//Native functions that call OpenSSL functionalities.
	private native void computeBlock(long computeP, byte[] in, byte[] out, int outOffset, int blockSize); 	//Computes the PRP on the given in block.
	private native void invertBlock(long invertP, byte[] in, byte[] out, int outOffset, int blockSize);		//Inverts the PRP on the given in block.
	private native void doOptimizedCompute(long computeP, byte[] inBytes, byte[] outBytes, int blockSize);	//Computes the PRP on the given in array.
	private native void doOptimizedInvert(long invertP, byte[] inBytes, byte[] outBytes, int blockSize);	//Inverts the PRP on the given in array.
	private native void deleteNative(long computeP, long invertP);											//Deleted the native objects.
	
	/**
	 * Default constructor. Uses default implementation of SecureRandom.
	 */
	public OpenSSLPRP(){
		//Call the general constructor with new SecureRandom object.
		this(new SecureRandom());
	}
	
	/**
	 * Constructor that lets the user choose the source of randomness to use.
	 * @param random source of randomness.
	 */
	public OpenSSLPRP(SecureRandom random){
		//Creates the native object that compute the PRP.
		this.random = random; //Sets the given random.
	}
	
	/**
	 * Constructor that lets the user choose the random algorithm to use.
	 * @param randNumGenAlg random number generator algorithm.
	 * @throws NoSuchAlgorithmException if the given algorithm is not valid.
	 */
	public OpenSSLPRP(String randNumGenAlg) throws NoSuchAlgorithmException{
		//Create the SecureRandom object and call the general constructor with it.
		this(SecureRandom.getInstance(randNumGenAlg));
	}

	@Override
	public boolean isKeySet() {
		return isKeySet;
	}

	/**
	 * This function should not be used to generate a key for the PRP and it throws UnsupportedOperationException.
	 * @throws UnsupportedOperationException 
	 */
	@Override
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		throw new UnsupportedOperationException("To generate a key for this prf object use the generateKey(int keySize) function");
	}

	/**
	 * Generates a secret key to initialize this PRP object.
	 * @param keySize is the required secret key size in bits.
	 * @return the generated secret key.
	 */
	@Override
	public SecretKey generateKey(int keySize) {
		SecretKey secretKey = null;
		//Looks for a default provider implementation of the key generation for PRP. 
		try {
			//Gets the KeyGenerator of this algorithm,
			KeyGenerator keyGen = KeyGenerator.getInstance(getAlgorithmName());
			//If the key size is zero or less - uses the default key size as implemented in the provider implementation,
			if(keySize <= 0){
				keyGen.init(random);
			//Else, uses the keySize to generate the key.
			} else {
				keyGen.init(keySize, random);
			}
			//Generates the key.
			secretKey = keyGen.generateKey();
		
		//Could not find a default provider implementation.
		//Then, generate a random string of bits of length keySize, which has to be greater than zero. 
		} catch (NoSuchAlgorithmException e) {
			//If the key size is zero or less - throw exception.
			if (keySize <= 0){
				throw new NegativeArraySizeException("Key size must be greater than 0");
			}
			if ((keySize % 8) != 0)  {
				throw new InvalidParameterException("Wrong key size: must be a multiple of 8");
			}	              

			//Creates a byte array of size keySize.
			byte[] genBytes = new byte[keySize/8];

			//Generates the bytes using the random.
			random.nextBytes(genBytes);
			//Creates a secretKey from the generated bytes.
			secretKey = new SecretKeySpec(genBytes, "");
		}
		
		return secretKey;
	}

	/** 
	 * Computes the permutation on the given block. <p>
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
		
		// We copy just the block we need to compute. else, the JNI will copy the whole array for nothing. 
		byte[] newIn = inBytes;
		if (inOff > 0){
			
			newIn = new byte[getBlockSize()];
			System.arraycopy(inBytes, inOff, newIn, 0, getBlockSize());
		}
		
		//Call the native code to perform computeBlock.
		computeBlock(computeP, newIn, outBytes, outOff, getBlockSize());
	}
	
	/** 
	 * Computes the permutation on the given array. 
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
			
		doOptimizedCompute(computeP, inBytes, outBytes, getBlockSize());
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
	 * Inverts the permutation on the given block.
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
		// Checks that the offsets are correct. 
		if ((inOff > inBytes.length) || (inOff+getBlockSize() > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		
		// The native object needs the message to begin at offset 0.
		// If the given offset is not 0 copy the msg to a new array. 
		byte[] newIn = inBytes;
		if (inOff > 0){
			newIn = new byte[getBlockSize()];
			System.arraycopy(inBytes, inOff, newIn, 0, getBlockSize());
		}
		
		//Call the native code to perform invert.
		invertBlock(invertP, newIn, outBytes, outOff, getBlockSize());	
	}
	
	/**
	 * Inverts the permutation on the given array. 
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
		
		//Call the native code to perform invert.
		doOptimizedInvert(invertP, inBytes, outBytes, getBlockSize());	
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
	 * Deletes the native objects
	 */
	protected void finalize() throws Throwable {

		// Delete from the dll the dynamic allocation.
		deleteNative(computeP, invertP);

		super.finalize();
	}
	
	static {
		//Loads the OpenSSL dll.
		 System.loadLibrary("OpenSSLJavaInterface");
	}
}
