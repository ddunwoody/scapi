package edu.biu.scapi.midLayer.symmetricCrypto.mac;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.logging.Level;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
	private boolean isMacStarted = false; 		// Set to false until startMac is called
	private boolean isKeySet = false;

	
	/**
	 * Default constructor
	 */
	public ScCbcMacPrepending() {
		this.prp = new BcAES();
		this.random = new SecureRandom();
	}
	
	
	/**
	 * Constructor that gets a prp name and sets it as the underlying prp.
	 * The source of randomness will be set with the default implementation.
	 * @param prpName the name of the underlying prp
	 * @throws FactoriesException if the creation of the prp failed
	 */
	public ScCbcMacPrepending(String prpName) throws FactoriesException {

		// creates a prf object
		PseudorandomFunction prf = PrfFactory.getInstance().getObject(prpName);
		// if the prf is not an instance of prp, throw exception
		if (!(prf instanceof PrpFixed)) {
			throw new IllegalArgumentException("the given name must be a prp name");
		}
		// sets the prp
		prp = (PrpFixed) prf;
		
		this.random = new SecureRandom();
	}

	/**
	 * Constructor that gets a prp name and sets it as the underlying prp.<p>
	 * The source of randomness will be set with the default implementation.<p>
	 * * It also gets the name of a Random Number Generator Algorithm to use to generate the source of randomness.<p>
	 * @param prpName the name of the underlying prp
	 * @param randNumGenAlg  the name of the RNG algorithm, for example "SHA1PRNG"
	 * @throws FactoriesException if the creation of the prp failed
	 */
	public ScCbcMacPrepending(String prpName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException {

		// creates a prf object
		PseudorandomFunction prf = PrfFactory.getInstance().getObject(prpName);
		// if the prf is not an instance of prp, throw exception
		if (!(prf instanceof PrpFixed)) {
			throw new IllegalArgumentException("the given name must be a prp fixed name");
		}
		// sets the prp
		prp = (PrpFixed) prf;
		
		this.random = SecureRandom.getInstance(randNumGenAlg);
	}

	/**
	 * Constructor that gets an initialized prp object and sets it as the underlying prp. 
	 * @param prpName the name of the underlying prp
	 */
	public ScCbcMacPrepending(PrpFixed prp){
		//Call other constructor using default implementation of SecureRandom
		this(prp, new SecureRandom());
	}

	/**
	 * Constructor that gets an initialized prp object and set it as the underlying prp. 
	 * After using this constructor, there is no need to call init.
	 * @param prpName the name of the underlying prp
	 */
	public ScCbcMacPrepending(PrpFixed prp, SecureRandom random) {
		// sets the class member prp to the given object.
		this.prp = prp;
		//Set the random variable.
		this.random = random;
	}

	
	/**
	 * Supply this cbc-mac with a secret key.
	 * @param secretKey secret key
	 * @throws InvalidKeyException
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException {
		// Supply the underlying prp with the key
		prp.setKey(secretKey);
		isKeySet = true;
	}

	public boolean isKeySet(){
		return isKeySet;
	}

	/**
	 * @return CBC-MAC with the underlying algorithm name
	 */
	public String getAlgorithmName() {

		return "CBC-MAC/" + prp.getAlgorithmName();
	}

	/**
	 * Returns the input block size in bytes.
	 * 	 * @return the input block size
	 */
	public int getMacSize() {
		// mac size is the same as block size
		return getBlockSize();
	}

	/**
	 * Generates a secret key to initialize this mac object.
	 * This function delegates the generation of the key to the underlying PRP. 
	 * It should only be used if the Secret Key is not a string of random bits of a specified length.
	 * @param keyParams parameters needed to create the key.
	 * @return the generated secret key
	 * @throws InvalidParameterSpecException 
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		return prp.generateKey(keyParams);
	}
	
	/**
	 * Generates a secret key to initialize this mac object.
	 * @param keySize the length of the key to generate, it must be greater than zero.
	 * @return the generated secret key
	 */
	public SecretKey generateKey(int keySize) {
		//First looks for a default provider implementation of the key generation for the underlying prp.
		//If found then return it. 
		//Otherwise it generate a random string of bits of length keySize 
		try {
			//gets the KeyGenerator of this algorithm
			KeyGenerator keyGen = KeyGenerator.getInstance(prp.getAlgorithmName());
			//if the key size is zero or less - uses the default key size as implemented in the provider implementation
			if(keySize <= 0){
				keyGen.init(random);
			//else, uses the keySize to generate the key
			} else {
				keyGen.init(keySize, random);
			}
			//generates the key
			return keyGen.generateKey();
		
		//Could not find a default provider implementation, 
		//then, generate a random string of bits of length keySize, which has to be greater that zero. 
		} catch (NoSuchAlgorithmException e) {
			//if the key size is zero or less - throw exception
			if (keySize < 0){
				throw new NegativeArraySizeException("key size must be greater than 0");
			}
			//creates a byte array of size keySize
			byte[] genBytes = new byte[keySize];

			//generates the bytes using the random
			//Do we need to seed random??
			random.nextBytes(genBytes);
			//creates a secretKey from the generated bytes
			SecretKey generatedKey = new SecretKeySpec(genBytes, "");
			return generatedKey;
		}
	}
	
	/**
	 * Pre-pends the length if the message to the message. 
	 * As a result, the mac will be calculated on [msgLength||msg].
	 * 
	 * @param msgLength the length of the message
	 */
	public void startMac(int msgLength){
		
		try {
			actualMsgLength = 0; // resets the msg
			expectedMsgLength = msgLength; // saves the msg length

			// get the bytes of the length
			byte[] len = BigInteger.valueOf(msgLength).toByteArray();

			// create an array of size getMacSize, copy the length to it and
			// pad the rest bytes with zeros
			byte[] prepending = new byte[getMacSize()];
			System.arraycopy(len, 0, prepending, 0, len.length);
			for (int i = len.length; i < getMacSize(); i++) {
				prepending[i] = 0;
			}
			tag = new byte[getMacSize()];
			// computes the mac operation of the msg length - the pre-pended
			// block of the mac computation
			prp.computeBlock(prepending, 0, tag, 0);

			isMacStarted = true; // sets the mac state to started
		} catch (IllegalBlockSizeException e) {
			// shouldn't occur since the tag is of size block size and the
			// msgLength size is small
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
	}

	/**
	 * Computes the CBC-Mac operation on the given msg and return the calculated tag.
	 * @param msg the message to operate the mac on
	 * @param offset the offset within the message array to take the bytes from
	 * @param msgLen the length of the message
	 * @return byte[] the return tag from the mac operation
	 */
	public byte[] mac(byte[] msg, int offset, int msgLen) {
		// calls start mac to pre- pend the length
		startMac(msgLen);
		// computes the mac operation of the msg
		return doFinal(msg, offset, msgLen);
	}

	/**
	 * verifies that the given tag is valid for the given message.
	 * @param msg the message to compute the cbc-mac on to verify the tag
	 * @param offset the offset within the message array to take the bytes from
	 * @param msgLength the length of the message
	 * @param tag the tag to verify
	 * @return true if the tag is the result of computing mac on the message. false, otherwise.
	 */
	public boolean verify(byte[] msg, int offset, int msgLength, byte[] tag){
		// if the tag size is not the mac size - returns false
		if (tag.length != getMacSize()) {
			return false;
		}
		// calculates the mac on the msg to get the real tag
		byte[] macTag = mac(msg, offset, msgLength);

		// compares the real tag to the given tag
		// for code-security reasons, the comparison is fully performed. that is, even if we know
		// already after the first few bits that the tag is not equal to the mac, we continue the
		// checking until the end of the tag bits
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
	 * @param msg the message to add
	 * @param offset the offset within the message array to take the bytes from
	 * @param msgLen the length of the message in bytes
	 */
	public void update(byte[] msg, int offset, int msgLen) {
		// msg is not marked as started
		if (!isMacStarted) {
			throw new IllegalStateException("to start the mac call the startMac function");
		}

		// msg is not aligned to the underlying prp's block size
		if ((msgLen % getMacSize()) != 0) {
			throw new IllegalArgumentException(
					"message should be alligned to the mac size, " + getMacSize() + " bits");
		}
		// calculates the number of blocks of size mac size
		int rounds = msgLen / getMacSize();

		// goes over the msg blocks
		for (int i = 0; i < rounds; i++) {
			// xor the tag with the current block in the message.
			// in order to avoid unnecessary allocation of memory, we put the
			// xor-ed bytes into tag
			for (int j = 0; j < getMacSize(); j++) {
				tag[j] = (byte) (tag[j] ^ msg[j + i * getMacSize()]);
			}
			try {
				// computes the tag of the current block. puts the result into
				// tag to avoid unnecessary allocating and copying of arrays
				prp.computeBlock(tag, 0, tag, 0);

				// increases the actual message size
				actualMsgLength += getMacSize();
			} catch (IllegalBlockSizeException e) {
				// shoudn't occur since the arguments are of size block size
				e.printStackTrace();
				Logging.getLogger().log(Level.WARNING, e.toString());
			}
		}
	}

	/**
	 * Completes the mac computation and puts the result tag in the tag array.
	 * @param msg the end of the message to mac
	 * @param offset the offset within the message array to take the bytes from
	 * @param msgLength the length of the message
	 * @return the result tag from the mac operation
	 */
	public byte[] doFinal(byte[] msg, int offset, int msgLen){
		//msg is not marked as started
		if(!isMacStarted){
			throw new IllegalStateException("to start the mac call the startMac function");
		}
		
		//number of bytes left to be aligned to the block size
		int pad = 0;
		
		//msg is not aligned to the underlying prp's block size
		if ((msgLen % getMacSize()) != 0){
			pad = getMacSize() - (msgLen % getMacSize());
		}
		
		//creates a new array that padded to be aligned to the mac size
		byte[] paddedMsg = new byte[msgLen + pad];
		//copy the msg to the beginning of the padded array
		System.arraycopy(msg, offset, paddedMsg, 0, msgLen);
		
		//if msg is not aligned to the underlying prp's block size, pads with zeroes
		if (pad > 0){
			for( int i=0; i<pad; i++){
				paddedMsg[msgLen+i] = 0;
			}
		}
		//number of blocks in size macSize
		int rounds = (msgLen+pad) / getMacSize();
	
		//goes over the msg blocks
		for( int i=0; i<rounds; i++){
			
			//xor the tag with the current block in the message.
			//in order to avoid unnecessary allocation of memory, we put the xor-ed bytes into tag
			for (int j=0; j<getMacSize(); j++){
				tag[j] = (byte) (tag[j] ^ paddedMsg[j+i*getMacSize()]);
			}
			try {
				//computes the tag of the current block. puts the result into tag to avoid unnecessary allocating and copying of arrays
				prp.computeBlock(tag, 0, tag, 0);
				
			} catch (IllegalBlockSizeException e) {
				// shoudn't occur since the arguments are of size block size
				e.printStackTrace();
				Logging.getLogger().log(Level.WARNING, e.toString());
			} 
		}
		//increases the actual message size
		actualMsgLength += msgLen;
		//if the given message is not in the expected size - throws exception
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
	 * @param inBytes the msg
	 * @param inOff the offset within the msg to take the bytes from
	 * @param outbytes the output array
	 * @param outOff the offset within the out array to put the result from
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws IllegalBlockSizeException{
		// calls the mac operation
		byte[] tag = mac(inBytes, inOff, getMacSize());
		// copies the return tag to the output array
		System.arraycopy(tag, 0, outBytes, outOff, getMacSize());
	}

	/**
	 * Computes the mac operation.
	 * @param inBytes the msg
	 * @param inOff the offset within the msg to take the bytes from
	 * @param inLen the length of the msg
	 * @param outbytes the output array
	 * @param outOff the offset within the out array to put the result from
	 * @param outLen the required length of the output array
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen,
			byte[] outBytes, int outOff, int outLen)
			throws IllegalBlockSizeException{
		// if the required length of the output array is not the mac size -
		// throws exception
		if (outLen != getMacSize()) {
			throw new IllegalBlockSizeException("output size should be " + getMacSize() + "bytes");
		}

		// calls the mac operation
		byte[] tag = mac(inBytes, inOff, inLen);
		// copies the return tag to the output array
		System.arraycopy(tag, 0, outBytes, outOff, getMacSize());
	}

	/**
	 * Computes the mac operation.
	 * @param inBytes the msg
	 * @param inOff the offset within the msg to take the bytes from
	 * @param inLen the length of the msg
	 * @param outbytes the output array
	 * @param outOff the offset within the out array to put the result from
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen,
			byte[] outBytes, int outOff) throws IllegalBlockSizeException{
		// calls the mac operation
		byte[] tag = mac(inBytes, inOff, inLen);
		// copies the return tag to the output array
		System.arraycopy(tag, 0, outBytes, outOff, getMacSize() / 8);

	}

}
