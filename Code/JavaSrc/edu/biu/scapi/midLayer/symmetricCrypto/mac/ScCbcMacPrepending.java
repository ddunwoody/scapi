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


package edu.biu.scapi.midLayer.symmetricCrypto.mac;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.logging.Level;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.prf.PrpFixed;
import edu.biu.scapi.primitives.prf.PseudorandomFunction;
import edu.biu.scapi.primitives.prf.bc.BcAES;
import edu.biu.scapi.tools.Factories.PrfFactory;

/**
 * Concrete class of CBC-Mac.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ScCbcMacPrepending implements CbcMac {

	private PrpFixed prp; 						// The underlying prp
	private SecureRandom random;				// Source of randomness used in key generation
	private int expectedMsgLength; 				// The length of the msg, as given in the startMac function
	private int actualMsgLength; 				// The length of the msg that the update function already got
	private byte[] tag; 						// The current calculated tag from the update function.
												// The result of the update function is saved in the tag to
												// avoid unnecessary allocation and copying of arrays
	private boolean isMacStarted; 				// Set to false until startMac is called

	
	/**
	 * Default constructor. Uses default implementation of PRP and SecureRandom.
	 */
	public ScCbcMacPrepending() {
		this(new BcAES(), new SecureRandom());
	}
	
	
	/**
	 * Constructor that gets a prp name and sets it as the underlying prp.
	 * The source of randomness will be set with the default implementation.
	 * @param prpName the name of the underlying prp
	 * @throws FactoriesException if the creation of the prp failed
	 * @throws IllegalArgumentException if the given name is not a valid PrpFixed name.
	 */
	public ScCbcMacPrepending(String prpName) throws FactoriesException {

		// Creates a prf object.
		PseudorandomFunction prf = PrfFactory.getInstance().getObject(prpName);
		// If the prf is not an instance of Prpfixed, throws exception.
		if (!(prf instanceof PrpFixed)) {
			throw new IllegalArgumentException("the given name must be a prp name");
		}
		// Sets the prp.
		prp = (PrpFixed) prf;
		// Sets default SecureRandom.
		this.random = new SecureRandom();
	}

	/**
	 * Constructor that gets a prp name and sets it as the underlying prp.<p>
	 * It also gets the name of a Random Number Generator Algorithm to use to generate the source of randomness.<p>
	 * @param prpName the name of the underlying prp.
	 * @param randNumGenAlg  the name of the RNG algorithm, for example "SHA1PRNG".
	 * @throws FactoriesException if the creation of the prp failed.
	 * @throws NoSuchAlgorithmException if the given randNumGenAlg is not a valid random number generator algorithm's name.
	 * @throws IllegalArgumentException if the given name is not a valid PrpFixed name.
	 */
	public ScCbcMacPrepending(String prpName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException {

		// Creates a prf object.
		PseudorandomFunction prf = PrfFactory.getInstance().getObject(prpName);
		// If the prf is not an instance of Prpfixed, throws exception.
		if (!(prf instanceof PrpFixed)) {
			throw new IllegalArgumentException("the given name must be a prp name");
		}
		// Sets the prp.
		prp = (PrpFixed) prf;
		// Sets default SecureRandom.
		this.random = SecureRandom.getInstance(randNumGenAlg);
	}

	/**
	 * Constructor that gets a prp object and sets it as the underlying prp. 
	 * @param prp the name of the underlying prp
	 */
	public ScCbcMacPrepending(PrpFixed prp){
		//Call other constructor using default implementation of SecureRandom
		this(prp, new SecureRandom());
	}

	/**
	 * Constructor that gets a prp object and set it as the underlying prp and a SecureRandom object to use as source of randomness. 
	 * @param prp the name of the underlying prp.
	 * @param random source of randomness.
	 */
	public ScCbcMacPrepending(PrpFixed prp, SecureRandom random) {
		// Sets the class member prp to the given object.
		this.prp = prp;
		//Set the random variable.
		this.random = random;
	}

	
	/**
	 * Supply this cbc-mac with a secret key.
	 * @param secretKey secret key
	 * @throws InvalidKeyException if the given key does not match the underlying prp of this CBC-MAC
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException {
		// Supply the underlying prp with the key
		prp.setKey(secretKey);
	}

	public boolean isKeySet(){
		return prp.isKeySet();
	}

	/**
	 * @return CBC-MAC with the underlying prp name
	 */
	public String getAlgorithmName() {

		return "CBC-MAC/" + prp.getAlgorithmName();
	}

	/**
	 * Returns the input block size in bytes.
	 * @return the input block size.
	 */
	public int getMacSize() {
		// Mac size is the same as block size.
		return getBlockSize();
	}

	/**
	 * Generates a secret key to initialize this mac object.
	 * This function delegates the generation of the key to the underlying PRP. 
	 * It should only be used if the Secret Key is not a string of random bits of a specified length.
	 * @param keyParams parameters needed to create the key.
	 * @return the generated secret key.
	 * @throws InvalidParameterSpecException  if the given keyParams does not match the underlying prp.
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		return prp.generateKey(keyParams);
	}
	
	/**
	 * Generates a secret key to initialize this mac object.
	 * @param keySize is the required secret key size in bits (it has to be greater than 0 a multiple of 8)
	 * @return the generated secret key.
	 */
	public SecretKey generateKey(int keySize) {
		return prp.generateKey(keySize);
	}
	
	/**
	 * Pre-pends the length of the message to the message. 
	 * As a result, the mac will be calculated on [msgLength||msg].
	 * @param msgLength the length of the message in bytes.
	 * @throws IllegalStateException if no secret key was set.
	 */
	public void startMac(int msgLength){
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		try {
			actualMsgLength = 0; // Resets the msg.
			expectedMsgLength = msgLength; // Saves the msg length.

			// Gets the bytes of the length.
			byte[] len = BigInteger.valueOf(msgLength).toByteArray();

			// Creates an array of size getMacSize, copies the length to it and
			// pads the rest bytes with zeros.
			byte[] prepending = new byte[getMacSize()];
			System.arraycopy(len, 0, prepending, 0, len.length);
			for (int i = len.length; i < getMacSize(); i++) {
				prepending[i] = 0;
			}
			tag = new byte[getMacSize()];
			// Computes the mac operation of the msg length - the pre-pended
			// block of the mac computation.
			prp.computeBlock(prepending, 0, tag, 0);

			isMacStarted = true; // Sets the mac state to started.
		} catch (IllegalBlockSizeException e) {
			// Shouldn't occur since the tag is of size block size and the
			// msgLength size is small.
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
	}

	/**
	 * Computes the CBC-Mac operation on the given msg and returns the calculated tag.
	 * @param msg the message to calculate the mac on.
	 * @param offset the offset within the message array to take the bytes from.
	 * @param msgLen the length of the message in bytes.
	 * @return byte[] the return tag from the mac operation.
	 * @throws IllegalStateException if no secret key was set.
	 */
	public byte[] mac(byte[] msg, int offset, int msgLen) {
		if (!isKeySet()){
			throw new IllegalStateException("in order to encrypt a message this object must be initialized with private key");
		}
		// Calls start mac to pre- pend the length.
		startMac(msgLen);
		// Computes the mac operation of the msg.
		return doFinal(msg, offset, msgLen);
	}

	/**
	 * Verifies that the given tag is valid for the given message.
	 * @param msg the message to compute the cbc-mac on to verify the tag.
	 * @param offset the offset within the message array to take the bytes from.
	 * @param msgLength the length of the message in bytes.
	 * @param tag the tag to verify.
	 * @return true if the tag is the result of computing mac on the message. false, otherwise.
	 * @throws IllegalStateException if no secret key was set.
	 */
	public boolean verify(byte[] msg, int offset, int msgLength, byte[] tag){
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		// If the tag size is not the mac size - returns false.
		if (tag.length != getMacSize()) {
			return false;
		}
		// Calculates the mac on the msg to get the real tag.
		byte[] macTag = mac(msg, offset, msgLength);

		// Compares the real tag to the given tag.
		// For code-security reasons, the comparison is fully performed. That is, even if we know
		// already after the first few bits that the tag is not equal to the mac, we continue the
		// checking until the end of the tag bits.
		boolean equal = true;
		int length = macTag.length;
		for (int i = 0; i < length; i++) {
			if (macTag[i] != tag[i]) {
				equal = false;
			}
		}
		return equal;
	}

	/**
	 * Adds the byte array to the existing message to mac.
	 * @param msg the message to add.
	 * @param offset the offset within the message array to take the bytes from.
	 * @param msgLen the length of the message in bytes.
	 * @throws IllegalStateException if no secret key was set.
	 * @throws IllegalStateException if the startMac function was not called.
	 * @throws IllegalArgumentException if the given message is not aligned to this Mac size.
	 */
	public void update(byte[] msg, int offset, int msgLen) {
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		// Msg is not marked as started.
		if (!isMacStarted) {
			throw new IllegalStateException("to start the mac call the startMac function");
		}

		// Msg is not aligned to the underlying prp's block size.
		if ((msgLen % getMacSize()) != 0) {
			throw new IllegalArgumentException("message should be aligned to the mac size, " + getMacSize() + " bytes");
		}
		// Calculates the number of blocks of size mac size.
		int rounds = msgLen / getMacSize();

		// Goes over the msg blocks.
		for (int i = 0; i < rounds; i++) {
			// Xores the tag with the current block in the message.
			// In order to avoid unnecessary allocation of memory, we put the xor-ed bytes into tag.
			for (int j = 0; j < getMacSize(); j++) {
				tag[j] = (byte) (tag[j] ^ msg[j + i * getMacSize()]);
			}
			try {
				// Computes the tag of the current block. Puts the result into
				// tag to avoid unnecessary allocating and copying of arrays.
				prp.computeBlock(tag, 0, tag, 0);

				// Increases the actual message size.
				actualMsgLength += getMacSize();
			} catch (IllegalBlockSizeException e) {
				// Shouldn't occur since the arguments are of size block size.
				e.printStackTrace();
				Logging.getLogger().log(Level.WARNING, e.toString());
			}
		}
	}

	/**
	 * Completes the mac computation and puts the result tag in the tag array.
	 * @param msg the end of the message to mac.
	 * @param offset the offset within the message array to take the bytes from.
	 * @param msgLen the length of the message in bytes.
	 * @return the result tag from the mac operation.
	 * @throws IllegalStateException if no secret key was set.
	 */
	public byte[] doFinal(byte[] msg, int offset, int msgLen){
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		//Msg is not marked as started.
		if(!isMacStarted){
			throw new IllegalStateException("to start the mac call the startMac function");
		}
		
		//Number of bytes left to be aligned to the block size.
		int pad = 0;
		
		//Msg is not aligned to the underlying prp's block size.
		if ((msgLen % getMacSize()) != 0){
			pad = getMacSize() - (msgLen % getMacSize());
		}
		
		//Creates a new array that padded to be aligned to the mac size.
		byte[] paddedMsg = new byte[msgLen + pad];
		//copy the msg to the beginning of the padded array.
		System.arraycopy(msg, offset, paddedMsg, 0, msgLen);
		
		//If msg is not aligned to the underlying prp's block size, pads with zeroes.
		if (pad > 0){
			for( int i=0; i<pad; i++){
				paddedMsg[msgLen+i] = 0;
			}
		}
		//Number of blocks in size macSize.
		int rounds = (msgLen+pad) / getMacSize();
	
		//Goes over the msg blocks.
		for( int i=0; i<rounds; i++){
			
			//Xores the tag with the current block in the message.
			//In order to avoid unnecessary allocation of memory, we put the xor-ed bytes into tag.
			for (int j=0; j<getMacSize(); j++){
				tag[j] = (byte) (tag[j] ^ paddedMsg[j+i*getMacSize()]);
			}
			try {
				//Computes the tag of the current block. Puts the result into tag to avoid unnecessary allocating and copying of arrays.
				prp.computeBlock(tag, 0, tag, 0);
				
			} catch (IllegalBlockSizeException e) {
				// Shouldn't occur since the arguments are of size block size
				e.printStackTrace();
				Logging.getLogger().log(Level.WARNING, e.toString());
			} 
		}
		//Increases the actual message size.
		actualMsgLength += msgLen;
		//If the given message is not in the expected size - throws exception.
		if(actualMsgLength != expectedMsgLength){
			throw new IllegalArgumentException("msg size is not matching the expected size, as given in the startMac function");
		}
		return tag;
	}

	public int getBlockSize() {
		return prp.getBlockSize();
	}

	/**
	 * Computes the mac operation.
	 * @param inBytes the msg.
	 * @param inOff the offset within the msg to take the bytes from.
	 * @param outBytes the output array.
	 * @param outOff the offset within the out array to put the result from.
	 * @throws IllegalStateException if no secret key was set.
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff) {
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		// Calls the mac operation.
		byte[] tag = mac(inBytes, inOff, getMacSize());
		// Copies the return tag to the output array.
		System.arraycopy(tag, 0, outBytes, outOff, getMacSize());
	}

	/**
	 * Computes the mac operation.
	 * @param inBytes the msg.
	 * @param inOff the offset within the msg to take the bytes from.
	 * @param inLen the length of the msg in bytes.
	 * @param outBytes the output array.
	 * @param outOff the offset within the out array to put the result from.
	 * @param outLen the required length of the output array in bytes. Should be equal to this mac size.
	 * @throws IllegalStateException if no secret key was set.
	 * @throws IllegalBlockSizeException if outLen is not equal to this mac size.
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen)
			throws IllegalBlockSizeException{
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		// If the required length of the output array is not the mac size - throws exception.
		if (outLen != getMacSize()) {
			throw new IllegalBlockSizeException("output size should be " + getMacSize() + "bytes");
		}

		// Calls the mac operation.
		byte[] tag = mac(inBytes, inOff, inLen);
		// Copies the return tag to the output array.
		System.arraycopy(tag, 0, outBytes, outOff, getMacSize());
	}

	/**
	 * Computes the mac operation.
	 * @param inBytes the msg.
	 * @param inOff the offset within the msg to take the bytes from.
	 * @param inLen the length of the msg in bytes.
	 * @param outBytes the output array.
	 * @param outOff the offset within the out array to put the result from.
	 * @throws IllegalStateException if no secret key was set.
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff){
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		// Calls the mac operation.
		byte[] tag = mac(inBytes, inOff, inLen);
		// Copies the return tag to the output array.
		System.arraycopy(tag, 0, outBytes, outOff, getMacSize());

	}

}
