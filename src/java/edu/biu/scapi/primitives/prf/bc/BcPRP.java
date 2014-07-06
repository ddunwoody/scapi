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


package edu.biu.scapi.primitives.prf.bc;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;

import edu.biu.scapi.primitives.prf.PrpFixed;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;

/** 
 * A general adapter class of PrpFixed for Bouncy Castle. 
 * This class implements all the functionality by passing requests to the adaptee interface BlockCipher. 
 * A concrete PRP such as AES represented by the class BcAES only passes the AESEngine object in the constructor 
 * to the base class. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 * 
 */
public abstract class BcPRP implements PrpFixed{
	
	private BlockCipher bcBlockCipher = null;//bc block cipher
	private CipherParameters bcParams = null;//bc parameters
	private boolean forEncryption = true;//set for true. If decryption is needed the flag will be set to false. 
	protected SecretKey secretKey = null;
	private SecureRandom random;
	protected boolean isKeySet = false;//until init is called set to false.
	

	/** 
	 * Constructor that accepts a blockCipher to be the underlying blockCipher.
	 * 
	 * @param bcBlockCipher the underlying BC block cipher
	 */
	public BcPRP(BlockCipher bcBlockCipher) {
		//creates random and call the other constructor
		this(bcBlockCipher, new SecureRandom());
		
	}
	
	/** 
	 * Constructor that accepts a blockCipher to be the underlying blockCipher and secureRadom.
	 * 
	 * @param bcBlockCipher the underlying BC block cipher
	 * @param random source of randomness to use
	 */
	public BcPRP(BlockCipher bcBlockCipher, SecureRandom random) {
		
		this.bcBlockCipher = bcBlockCipher;
		this.random = random;
	}


	/** 
	 * Initializes this PRP with the given secret key.
	 * @param secretKey secret key
	 * @throws InvalidKeyException 
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException {
		
		/*
		 * Creates the relevant BC parameters to pass when inverting or computing.
		 */
		
		//init parameters
		this.secretKey = secretKey;

		//get the parameters converted to BC.
		bcParams = BCParametersTranslator.getInstance().translateParameter(secretKey);
			
		//at the beginning forEncryption is set to true. Initialize the BC block cipher.
		bcBlockCipher.init(forEncryption, bcParams);
			
		isKeySet = true; //marks this object as initialized
			
		
	}
	
	public boolean isKeySet(){
		return isKeySet;
	}
	
	
	/**
	 * @return the name of the underlying blockCipher
	 */
	public String getAlgorithmName() {
		return bcBlockCipher.getAlgorithmName();
	}

	/**  
	 * @return the block size of the underlying blockCipher in bytes.
	 */
	public int getBlockSize(){
		
		return bcBlockCipher.getBlockSize();
	}
	
	
	/**
	 * Generates a secret key to initialize this PRP object.
	 * @param keySize is the required secret key size in bits (it has to be greater than 0 or a multiple of 8) 
	 * @return the generated secret key 
	 */
	public SecretKey generateKey(int keySize){
		SecretKey secretKey = null;
		//Looks for a default provider implementation of the key generation for this prp. 
		//The current prps we use are AES and TripleDes that exists in the default provider implementation.
		//If found then return it. 
		try {
			//gets the KeyGenerator of this algorithm
			KeyGenerator keyGen = KeyGenerator.getInstance(getAlgorithmName());
			//if the key size is zero or less - uses the default key size as implemented in the provider implementation
			if(keySize <= 0){
				keyGen.init(random);
				//else, uses the keySize to generate the key
			} else {
				keyGen.init(keySize, random);
			}
			//generates the key
			secretKey = keyGen.generateKey();
			
			return secretKey;
		
		//Could not find a default provider implementation, 
		//then, generate a random string of bits of length keySize, which has to be greater than zero. 
		} catch (NoSuchAlgorithmException e) {
			//if the key size is zero or less - throw exception
			if (keySize <= 0){
				throw new NegativeArraySizeException("Key size must be greater than 0");
			}
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

	}

	/** 
	 * Computes the underlying permutation. <p>
	 * 
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute.
	 * @param outOff output offset in the outBytes array to put the result from
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff) {
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		// checks that the offset and length are correct 
		if ((inOff > inBytes.length) || (inOff+getBlockSize() > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		//if the bc block cipher is not already in encryption mode initializes the block cipher with forEncryption=true
		if(forEncryption==false){
			forEncryption = true;
			//init the bcBlockCipher for encryption(true)
			bcBlockCipher.init(forEncryption, bcParams);
		}
		//does the computeBlock
		bcBlockCipher.processBlock(inBytes, inOff, outBytes, outOff);
	}
	
	/**
	 * This function is provided in the interface especially for the sub-family PrfVaryingInputLength, which may have variable input length.
	 * Since this is a prp, the input length is fixed with the block size, so this function normally shouldn't be called. 
	 * If the user still wants to use this function, the input length should be the same as the block size. Otherwise, throws an exception.
	 * 
	 * @param inBytes input bytes to compute
	 * @param inLen the length of the input array
	 * @param inOffset input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert
	 * @param outOffset output offset in the outBytes array to put the result from
	 */

	public void computeBlock(byte[] inBytes, int inOffset, int inLen, byte[] outBytes, int outOffset) throws IllegalBlockSizeException{
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//the checks on the offset and length is done in the computeBlock (inBytes, inOffset, outBytes, outOffset)
		if(inLen==getBlockSize()) //checks that the input length is the same as the block size.
			computeBlock(inBytes, inOffset, outBytes, outOffset);
		else
			throw new IllegalBlockSizeException("Wrong size");
	}
	
	/** 
	 * This function is provided in the interface especially for the sub-family PrfVaryingIOLength, which may have variable input/output lengths.
	 * Since both Input and output variables are fixed this function should not normally be called. 
	 * If the user still wants to use this function, the input and output lengths should be the same as 
	 * the result of <code>getBlockSize</code>, otherwise, throws an exception.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute.
	 * @param outOff output offset in the outBytes array to put the result from
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen)	throws IllegalBlockSizeException{
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//the checks on the offset and length are done in the computeBlock(inBytes, inOff, outBytes, outOff)
		if (inLen==outLen && inLen==getBlockSize()) //checks that the lengths are the same as the block size
			computeBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("Wrong size");			
	}
	
	/** 
	 * Inverts the underlying permutation.
	 * 
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert
	 * @param outOff output offset in the outBytes array to put the result from
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,	int outOff) {
		/*
		 * Calls the underlying bc block cipher processBlock. Since we wish to invertBlock we first set the flag
		 * of forEncryption to false.
		 */
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		// checks that the offsets are correct 
		if ((inOff > inBytes.length) || (inOff+getBlockSize() > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		//if the bc block cipher is not already in decryption mode init the block cipher with forEncryption=false
		if(forEncryption==true){
			forEncryption = false;
			//init the bcBlockCipher for encryption(true)
			bcBlockCipher.init(forEncryption, bcParams);
		}
		//does the invertBlock
		bcBlockCipher.processBlock(inBytes, inOff, outBytes, outOff);
	}

	
	
	/**
	 * This function is provided in the interface especially for the sub-family PrpVarying, which may have variable input/output lengths.
	 * Since in this case, both input and output variables are fixed this function should not normally be called. 
	 * If the user still wants to use this function, the specified argument <code>len</code> should be the same as 
	 * the result of <code>getBlockSize</code>, otherwise, throws an exception. 
	 * @param inBytes input bytes to invert
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert.
	 * @param outOff output offset in the outBytes array to put the result from
	 * @param len the length of the input and the output.
	 * @throws IllegalBlockSizeException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,	int outOff, int len) throws IllegalBlockSizeException{
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//the checks of the offset and lengths are done in the invertBlock(inBytes, inOff, outBytes, outOff)
		if (len==getBlockSize()) //checks that the length is the same asthe block size
			invertBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("Wrong size");
		
	}


}
