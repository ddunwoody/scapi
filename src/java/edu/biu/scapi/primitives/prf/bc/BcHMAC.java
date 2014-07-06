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

import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.macs.HMac;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.prf.Hmac;
import edu.biu.scapi.tools.Factories.BCFactory;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;



/** 
 * Adapter class that wraps the Hmac of bouncy castle.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class BcHMAC implements Hmac {
	/*
	 * Our class Hmac is an adapter class for the adaptee class HMac of BC.  
	 */
	private HMac hMac;							//The underlying wrapped hmac of BC.
	private boolean isKeySet = false;			//until init is called set to false.
	private SecureRandom random;				//source of randomness used in key generation

	/**
	 * Default constructor that uses SHA1.
	 * @throws FactoriesException if BC has no hash function corresponding to the given hash.
	 */
	public BcHMAC() {
		//creates SHA1 and secure random and than uses the extended constructor
		try{
			construct("SHA-1", new SecureRandom());
		}
		catch(FactoriesException e){
			//No need to do anything here since this exception cannot happen because we provide an BCSha1 class which the class the Factory needs to call.
		}
	}
	
	/** 
	 * This constructor receives an hashName and build the underlying hmac accoring to it. It can be called from the factory.
	 * @param hashName - the hash function to translate into digest of bc hmac.
	 * @throws FactoriesException if there is no hash function with given name.
	 */
	public BcHMAC(String hashName) throws FactoriesException{
			construct(hashName, new SecureRandom());
	}
	
	/** 
	 * This constructor receives an hashName and build the underlying hmac according to it. It can be called from the factory.
	 * @param hashName - the hash function to translate into digest of bc hmac.
	 * @param randNumGenAlg - the random number generator algorithm to use.
	 * @throws FactoriesException if there is no hash function with given name.
	 * @throws NoSuchAlgorithmException 
	 */
	public BcHMAC(String hashName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException {
		construct(hashName, SecureRandom.getInstance(randNumGenAlg));
	}

	public BcHMAC(String hashName, SecureRandom random) throws FactoriesException, NoSuchAlgorithmException {
		construct(hashName, random);
	}

	/**
	 * This constructor gets a SCAPI collision resistant hash to be the underlying hash and retrieves the name of the hash in
	 * order to create the related digest for the BC Hmac this class uses.
	 * @param hash - the underlying collision resistant hash 
	 * @throws FactoriesException if BC has no hash function corresponding to the given hash.
	 */
	public BcHMAC(CryptographicHash hash) throws FactoriesException{
		//creates random and uses the extended constructor
		this(hash, new SecureRandom());
	}
	
	/**
	 * This constructor gets a random and a SCAPI collision resistant hash to be the underlying hash and retrieves the name of the hash in
	 * order to create the related digest for the BC Hmac this class uses.
	 * @param hash - the underlying collision resistant hash 
	 * @param random
	 * @throws FactoriesException if BC has no hash function corresponding to the given hash.
	 */
	public BcHMAC(CryptographicHash hash, SecureRandom random) throws FactoriesException{
		construct(hash.getAlgorithmName(), random);
	}
	
	private void construct(String hashName, SecureRandom random) throws FactoriesException{
		//passes a digest to the hmac.
		hMac = new HMac(BCFactory.getInstance().getDigest(hashName));
		//sets the random
		this.random = random;
		// Get 1024 random bits, this causes the random object to seed itself. Since the seeding might be a time-consuming operation 
		//it makes sense to do it once at the beginning, and then use the seeded object.
		byte[] bytes = new byte[1024/8];
	    random.nextBytes(bytes);

	}
	/** 
	 * Initializes this hmac with a secret key.
	 * @param secretKey the secret key 
	 */
	public void setKey(SecretKey secretKey) {
		
		CipherParameters bcParams; 
		//gets the relevant BC cipher parameter
		bcParams = BCParametersTranslator.getInstance().translateParameter(secretKey);
		
		//passes the key parameter to bc hmac
		hMac.init(bcParams);
		
		//sets flag to true. Object is initializing.
		isKeySet = true;
		
	}
	
	public boolean isKeySet(){
		return isKeySet;
	}
	
	/** 
	 * @return the name from BC hmac
	 */
	public String getAlgorithmName() {
		
		return hMac.getAlgorithmName();
	}

	/**
	 * @return the block size of the BC hmac in bytes
	 */
	public int getBlockSize(){
		return hMac.getMacSize();
	}
	
	/** 
	 * This function is provided in the interface especially for the sub-family Prp, which have fixed input/output lengths.
	 * Since in this case the input is not fixed, it must be supplied and this function should not be called. 
	 * If the user still calls this function, throws an exception.
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff) throws IllegalBlockSizeException{
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		
		throw new IllegalBlockSizeException("Size of input is not specified");
	}
	
	/**
	 * This function is provided in the interface especially for the sub-family PrfVaryingIOLength, which have varying input/output lengths.
	 * Since in this case the output variable is fixed this function should not normally be called. 
	 * If the user still wants to use this function, the specified argument outLen should be the same as 
	 * the result of getMacSize from BC, otherwise, throws an exception. 
	 * 
	 * @param inBytes input bytes to compute
	 * @param inLen the length of the input array
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to put the result from
	 * @param outLen the length of the output array
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen) throws IllegalBlockSizeException{
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//the checks of the offsets and lengths are done in the conputeBlock (inBytes, inOff, inLen, outBytes, outOff)
		//make sure the output size is correct
		if(outLen==hMac.getMacSize())
			computeBlock(inBytes, inOff, inLen, outBytes, outOff);
		else
			throw new IllegalBlockSizeException("Output size is incorrect");
	}
	
	/**
	 * Computes the function using the secret key. 
	 * The user supplies the input byte array and the offset from 
	 * which to take the data from. Also since the input is not fixed the input length is supplied as well. 
	 * The user also supplies the output byte array as well as the offset. 
	 * The computeBlock function will put the output starting at the offset. 
	 * 
	 * @param inBytes input bytes to compute
	 * @param inLen the length of the input array
	 * @param inOffset input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOffset output offset in the outBytes array to put the result from
	 */
	public void computeBlock(byte[] inBytes, int inOffset, int inLen,
			byte[] outBytes, int outOffset) {
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		// checks that the offset and length are correct 
		if ((inOffset > inBytes.length) || (inOffset+inLen > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOffset > outBytes.length) || (outOffset+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		//passes the input bytes to update
		hMac.update(inBytes, inOffset, inLen);
		
		//gets the output results through doFinal
		hMac.doFinal(outBytes, outOffset);
	}
	
	/**
	 * Generates a secret key to initialize this prf object.
	 * @param keyParams algorithmParameterSpec contains the required secret key size in bits 
	 * @return the generated secret key
	 * @throws InvalidParameterSpecException 
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException{
		throw new UnsupportedOperationException("To generate a key for this HMAC object use the generateKey(int keySize) function");
	}
	
	/**
	 * Generates a secret key to initialize this HMac object.
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
	 * Returns the input block size in bytes
	 * @return the input block size
	 */
	public int getMacSize(){
		return getBlockSize();
	}
	
	/**
	 * Computes the hmac operation on the given msg and return the calculated tag
	 * @param msg the message to operate the mac on
	 * @param offset the offset within the message array to take the bytes from
	 * @param msgLen the length of the message
	 * @return byte[] the return tag from the mac operation
	 */
	public byte[] mac(byte[] msg, int offset, int msgLen){
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//creates the tag
		byte[] tag = new byte[getMacSize()];
		//computes the hmac operation
		computeBlock(msg, offset, msgLen, tag, 0);
		//returns the tag
		return tag;
	}
	
	/**
	 * verifies that the given tag is valid for the given message
	 * @param msg the message to compute the mac on to verify the tag
	 * @param offset the offset within the message array to take the bytes from
	 * @param msgLength the length of the message
	 * @param tag the tag to verify
	 * @return true if the tag is the result of computing mac on the message. false, otherwise.
	 */
	public boolean verify(byte[] msg, int offset, int msgLength, byte[] tag){
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//if the tag size is not the mac size - returns false
		if (tag.length != getMacSize()){
			return false;
		}
		//calculates the mac on the msg to get the real tag
		byte[] macTag = mac(msg, offset, msgLength);
		
		//compares the real tag to the given tag
		//for code-security reasons, the comparison is fully performed. that is, even if we know 
		//already after the first few bits that the tag is not equal to the mac, we continue the 
		//checking until the end of the tag bits
		boolean equal = true;
		int length = macTag.length;
		for (int i=0;i<length; i++){
			if (macTag[i] != tag[i]){
				equal = false;
			}
		}
		return equal;	
	}
	
	/**
	 * Adds the byte array to the existing message to mac.
	 * @param msg the message to add
	 * @param offset the offset within the message array to take the bytes from
	 * @param msgLen the length of the message
	 */
	public void update(byte[] msg, int offset, int msgLen){
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//calls the underlying hmac update
		hMac.update(msg, offset, msgLen);
	}
	
	/**
	 * Completes the mac computation and puts the result tag in the tag array.
	 * @param msg the end of the message to mac
	 * @param offset the offset within the message array to take the bytes from
	 * @param msgLength the length of the message
	 * @return the result tag from the mac operation
	 */
	public byte[] doFinal(byte[] msg, int offset, int msgLength){
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//updates the last msg block
		update(msg, offset, msgLength);
		//creates the tag
		byte[] tag = new byte[getMacSize()];
		//calls the underlying hmac doFinal function
		hMac.doFinal(tag, 0);
		//returns the tag
		return tag;
	}
	
	

}
