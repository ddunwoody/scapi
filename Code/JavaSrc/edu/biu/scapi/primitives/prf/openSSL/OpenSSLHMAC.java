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
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.prf.Hmac;

/**
 * Concrete class of PRF family for Hmac. This class wraps the implementation of OpenSSL library.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OpenSSLHMAC implements Hmac {
	
	private long hmac;					//Pointer to the native hmac.
	private boolean isKeySet;			//until setKey is called set to false.
	private SecureRandom random;		//source of randomness used in key generation
	
	//Native functions that implements Hmac using OpenSSL functions.
	private native long createHMAC(String hashName);	//Creates the native Hmac object.
	private native void setKey(long hmac, byte[] key);	//Sets the key for the native Hmac object.
	private native int getNativeBlockSize(long hmac);	//Returns the block size of this Hmac object.
	private native String getName(long hmac);			//Returns the name of the underlying hash.
	private native void updateNative(long hmac, byte[] in, int inOffset, int inLen);//Updates the Hmac eith the given in array.
	private native void updateFinal(long hmac, byte[] out, int outOffset);//Finalize the Hmac operation and puts the result in the given out array.
	private native void deleteNative(long hmac);		//Deletes the native object.
	
	/**
	 * Default constructor that uses SHA1.
	 */
	public OpenSSLHMAC() {
		//Creates SHA1 and secure random and than uses the other constructor.
		try{
			construct("SHA-1", new SecureRandom());
		}
		catch(FactoriesException e){
			//No need to do anything here since this exception cannot happen because we provide a SHA-1 implementation.
		}
	}
	
	/** 
	 * This constructor receives a hashName and builds the underlying hmac according to it. It can be called from the factory.
	 * @param hashName - the hash function to translate into OpenSSL's hash.
	 * @throws FactoriesException if there is no hash function with given name.
	 */
	public OpenSSLHMAC(String hashName) throws FactoriesException{
		construct(hashName, new SecureRandom());
	}
	
	/** 
	 * This constructor receives an hashName and build the underlying hmac according to it. It can be called from the factory.
	 * @param hashName - the hash function to translate into OpenSSL's hash.
	 * @param randNumGenAlg - the random number generator algorithm to use.
	 * @throws FactoriesException if there is no hash function with given name.
	 * @throws NoSuchAlgorithmException if there is no random algorithm with the given name. 
	 */
	public OpenSSLHMAC(String hashName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException {
		construct(hashName, SecureRandom.getInstance(randNumGenAlg));
	}

	/** 
	 * This constructor receives an hashName and build the underlying hmac according to it. It can be called from the factory.
	 * @param hashName - the hash function to translate into OpenSSL's hash.
	 * @param random - the random object to use.
	 * @throws FactoriesException if there is no hash function with given name.
	 */
	public OpenSSLHMAC(String hashName, SecureRandom random) throws FactoriesException {
		construct(hashName, random);
	}

	/**
	 * This constructor gets a SCAPI CryptographicHash to be the underlying hash and retrieves the name of the hash in
	 * order to create the related OpenSSL's hash.
	 * @param hash - the underlying hash to use
	 * @throws FactoriesException if there is no hash function with given name.
	 */
	public OpenSSLHMAC(CryptographicHash hash) throws FactoriesException{
		//Creates random and uses the other constructor.
		this(hash, new SecureRandom());
	}
	
	/**
	 * This constructor gets a random and a SCAPI CryptographicHash to be the underlying hash and retrieves the name of the hash in
	 * order to create the related OpenSSL's hash.
	 * @param hash - the underlying hash to use.
	 * @param random the random object to use.
	 * @throws FactoriesException if there is no hash function with given name.
	 */
	public OpenSSLHMAC(CryptographicHash hash, SecureRandom random) throws FactoriesException{
		construct(hash.getAlgorithmName(), random);
	}
	
	private void construct(String hashName, SecureRandom random) throws FactoriesException{
		
		/*
		 * The way we call the hash is not the same as OpenSSL. For example: we call "SHA-1" while OpenSSL calls it "SHA1".
		 * So the hyphen should be deleted.
		 */
		String name = hashName; 
		if(hashName.contains("-")){
			String[] parts = hashName.split("-");
			name = "";
			for (int i=0; i<parts.length; i++)
				name += parts[i];
		}
		
		hmac = createHMAC(name);
		//Sets the random.
		this.random = random;

	}
	/** 
	 * Initializes this hmac with a secret key.
	 * @param secretKey the secret key 
	 */
	public void setKey(SecretKey secretKey) {
		setKey(hmac, secretKey.getEncoded());
		
		//Sets flag to true. Object is initialized.
		isKeySet = true;
		
	}
	
	public boolean isKeySet(){
		return isKeySet;
	}
	
	/** 
	 * @return the hmac name.
	 */
	public String getAlgorithmName() {
		//getName function returns the name of the underlying hash.
		return "Hmac/"+getName(hmac);
	}

	/**
	 * @return the block size of the hmac in bytes.
	 */
	public int getBlockSize(){
		return getNativeBlockSize(hmac);
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
		//The checks of the offsets and lengths are done in the conputeBlock (inBytes, inOff, inLen, outBytes, outOff).
		//Make sure the output size is correct
		if(outLen==getBlockSize())
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
	public void computeBlock(byte[] inBytes, int inOffset, int inLen, byte[] outBytes, int outOffset) {
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		// Check that the offset and length are correct.
		if ((inOffset > inBytes.length) || (inOffset+inLen > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOffset > outBytes.length) || (outOffset+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		
		//Passes the input bytes to update.
		updateNative(hmac, inBytes, inOffset, inLen);
		
		//Gets the output results through doFinal.
		updateFinal(hmac, outBytes, outOffset);
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
		//Generate a random string of bits of length keySize, which has to be greater that zero. 
		
		//If the key size is zero or less - throw exception.
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
	 * Returns the output block size in bytes.
	 * @return the output block size.
	 */
	public int getMacSize(){
		return getBlockSize();
	}
	
	/**
	 * Computes the hmac operation on the given msg and return the calculated tag.
	 * @param msg the message to operate the mac on.
	 * @param offset the offset within the message array to take the bytes from.
	 * @param msgLen the length of the message.
	 * @return byte[] the return tag from the mac operation.
	 */
	public byte[] mac(byte[] msg, int offset, int msgLen){
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//Creates the tag.
		byte[] tag = new byte[getMacSize()];
		//Computes the hmac operation.
		computeBlock(msg, offset, msgLen, tag, 0);
		//Returns the tag.
		return tag;
	}
	
	/**
	 * Verifies that the given tag is valid for the given message.
	 * @param msg the message to compute the mac on to verify the tag.
	 * @param offset the offset within the message array to take the bytes from.
	 * @param msgLength the length of the message.
	 * @param tag the tag to verify.
	 * @return true if the tag is the result of computing mac on the message. false, otherwise.
	 */
	public boolean verify(byte[] msg, int offset, int msgLength, byte[] tag){
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//If the tag size is not the mac size - returns false.
		if (tag.length != getMacSize()){
			return false;
		}
		//Calculates the mac on the msg to get the real tag.
		byte[] macTag = mac(msg, offset, msgLength);
		
		//Compares the real tag to the given tag.
		//For code-security reasons, the comparison is fully performed. that is, even if we know already after the first few bits 
		//that the tag is not equal to the mac, we continue the checking until the end of the tag bits.
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
	 * @param msg the message to add.
	 * @param offset the offset within the message array to take the bytes from.
	 * @param msgLen the length of the message.
	 */
	public void update(byte[] msg, int offset, int msgLen){
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//Calls the underlying hmac update.
		updateNative(hmac, msg, offset, msgLen);
	}
	
	/**
	 * Completes the mac computation and puts the result tag in the tag array.
	 * @param msg the end of the message to mac.
	 * @param offset the offset within the message array to take the bytes from.
	 * @param msgLength the length of the message.
	 * @return the result tag from the mac operation.
	 */
	public byte[] doFinal(byte[] msg, int offset, int msgLength){
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		//Updates the last msg block.
		update(msg, offset, msgLength);
		//Creates the tag.
		byte[] tag = new byte[getMacSize()];
		//Calls the underlying hmac doFinal function.
		updateFinal(hmac, tag, 0);
		//Returns the tag.
		return tag;
	}
	
	/**
	 * Deletes the native object.
	 */
	protected void finalize() throws Throwable {

		// Delete from the dll the dynamic allocation.
		deleteNative(hmac);

		super.finalize();
	}
	
	static {
		//loads the OpenSSL dll.
		 System.loadLibrary("OpenSSLJavaInterface");
	}

}
