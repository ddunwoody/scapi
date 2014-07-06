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


package edu.biu.scapi.primitives.prf.cryptopp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import edu.biu.scapi.primitives.prf.AES;

/**
 * Concrete class of prf family for AES. This class wraps the implementation of Crypto++.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CryptoPpAES implements AES{

	private boolean isKeySet;
	private long aesCompute;		//native object used for compute blocks
	private long aesInvert;			//native object used for invert blocks
	private SecureRandom random;
	
	private native long createAESCompute();
	private native long createAESInvert();
	private native void setNativeKey(long aesCompute, long aesInvert, byte[] key);
	private native void computeBlock(long aesCompute, byte[] in, byte[] out, int outOffset, boolean forEncrypt);
	private native void optimizedCompute(long aesCompute, byte[] in, byte[] out, boolean forEncrypt);
	private native String getName(long aes);
	private native int getBlockSize(long aes);
	private native void deleteAES(long aesCompute, long aesInvert);
	
	/**
	 * Default constructor. Uses default implementation of SecureRandom.
	 */
	public CryptoPpAES(){
		//Call the general constructor with new SecureRandom object.
		this(new SecureRandom());
	}
	
	/**
	 * Constructor that lets the user choose the source of randomness to use.
	 * @param random source of randomness.
	 */
	public CryptoPpAES(SecureRandom random){
		//Creates the native objects that compute the AES permutation.
		//Crypto++ implement it such that there is an object for computing the AES permutation on the block 
		//and a different object for inverting the AES permutation on the block.
		aesCompute = createAESCompute();
		aesInvert = createAESInvert();
		this.random = random; //Sets the given random
	}
	
	/**
	 * Constructor that lets the user choose the random algorithm to use.
	 * @param randNumGenAlg random number generator algorithm.
	 * @throws NoSuchAlgorithmException if the given algorithm is not valid.
	 */
	public CryptoPpAES(String randNumGenAlg) throws NoSuchAlgorithmException{
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
		//Call native function that set the key to the native objects.
		setNativeKey(aesCompute, aesInvert, secretKey.getEncoded());
		
		isKeySet = true;
	}

	@Override
	public boolean isKeySet() {
		return isKeySet;
	}

	@Override
	public String getAlgorithmName() {
		return getName(aesCompute);
	}

	@Override
	public int getBlockSize(){
		//Call the native code to return the name of the Crypto++ algorithm.
		return getBlockSize(aesCompute);
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
		
		// The native AES object needs the message to begin at offset 0.
		// If the given offset is not 0 copy the msg to a new array. 
		byte[] newIn = inBytes;
		if (inOff > 0){
			newIn = new byte[inBytes.length];
			System.arraycopy(inBytes, inOff, newIn, 0, inBytes.length);
		}
		
		//Call the native code to perform computeBlock
		computeBlock(aesCompute, newIn, outBytes, outOff, true);
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
			
		optimizedCompute(aesCompute, inBytes, outBytes, true);
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
		
		// The native AES object needs the message to begin at offset 0.
		// If the given offset is not 0 copy the msg to a new array. 
		byte[] newIn = inBytes;
		if (inOff > 0){
			newIn = new byte[inBytes.length];
			System.arraycopy(inBytes, inOff, newIn, 0, inBytes.length);
		}
		
		//Call the native code to perform invert
		computeBlock(aesInvert, newIn, outBytes, outOff, false);	
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
		optimizedCompute(aesInvert, inBytes, outBytes, false);	
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

		// delete from the dll the dynamic allocation of AES pointers.
		deleteAES(aesCompute, aesInvert);

		super.finalize();
	}
	
	//Load the crypto++ dll.
	static {
        System.loadLibrary("CryptoPPJavaInterface");
	}
}
