package edu.biu.scapi.midLayer.symmetricCrypto.encryption;
/**
 * This class implements common functionality of Symmetric Encryption Schemes that must use a random IV
 */
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.midLayer.ciphertext.IVCiphertext;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.prf.PseudorandomPermutation;
import edu.biu.scapi.primitives.prf.bc.BcAES;
import edu.biu.scapi.tools.Factories.PrfFactory;

abstract class EncWithIVAbs implements SymmetricEnc {
	protected PseudorandomPermutation prp;
	protected SecureRandom random;
	
	
	/**
	 * Default constructor
	 */
	public EncWithIVAbs(){
		//Sets the default PRP
		this.prp = new BcAES();
		//Sets default random
		this.random = new SecureRandom();
	}
	
	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * A default source of randomness is used.
	 * @param prp specific Pseudorandom permutation, for example AES.
	 */
	public EncWithIVAbs(PseudorandomPermutation prp){
		this.prp = prp;
		//sets default random and padding scheme
		this.random = new SecureRandom();
	}
	
	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * Random object sets the source of randomness.
	 * This constructor gets and initialized Pseudorandom permutation.
	 * @param prp the name of a specific Pseudorandom permutation, for example "AES".
	 * @param random SecureRandom object to set the random member
	 */
	public EncWithIVAbs(PseudorandomPermutation prp, SecureRandom random) {
		//sets the prp and random
		this.prp = prp;
		this.random = random;
		//create default padding scheme
	}
	
	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * This constructor gets the name of a Pseudorandom permutation and is responsible for creating a corresponding instance.<p>
	 * A default source of randomness is used.
	 * @param prp the name of a specific Pseudorandom permutation, for example "AES".
	 * @throws FactoriesException 
	 */
	public EncWithIVAbs(String prpName) throws FactoriesException {
		// Creates a prp object and set this.prp to it
		prp = (PseudorandomPermutation) PrfFactory.getInstance().getObject(prpName);
		random = new SecureRandom();
	}
	
	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * This constructor gets the name of a Pseudorandom permutation and is responsible for creating a corresponding instance.<p>
	 * It also gets the name of a Random Number Generator Algorithm to use to generate the source of randomness
	 * @param prp the name of a specific Pseudorandom permutation, for example "AES".
	 * @param randNumGenAlg  the name of the RNG algorithm, for example "SHA1PRNG"
	 * @throws FactoriesException 
	 * @throws NoSuchAlgorithmException 
	 */
	public EncWithIVAbs(String prpName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException {
		//Creates a prp object and set this.prp to it
		prp = (PseudorandomPermutation) PrfFactory.getInstance().getObject(prpName);
		//Creates a SecureRandom object that implements the specified Random Number Generator (RNG) algorithm. 
		this.random = SecureRandom.getInstance(randNumGenAlg);
	}
	
	
	/**
	 * Supply the encryption scheme with a Secret Key.
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException{
		prp.setKey(secretKey); //Do we need to check that prp is not null? What if it is? What if the concrete implementation doesn't instantiate the prp?
	}

	/**
	 * Checks if this object has been given a SecretKey 
	 * @return true, if already initialized <p> false, otherwise.
	 * 
	 */
	public boolean isKeySet(){
		return prp.isKeySet();
	}
	
	
	/**
	 * Generates a secret key to initialize this encryption with IV  object.
	 * This function delegates the generation of the key to the underlying PRP. 
	 * It should only be used if the Secret Key is not a string of random bits of a specified length.
	 * @param keyParams parameters needed to create the key.
	 * @return the generated secret key
	 * @throws InvalidParameterSpecException 
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keyParams ) throws InvalidParameterSpecException{
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
	 * This function encrypts a plaintext. It lets the system choose the random IV.
	 * @return  an IVCiphertext, which contains the IV used and the encrypted data.
	 */
	public SymmetricCiphertext encrypt(Plaintext plaintext) {	
		//Allocate space for the IV.
		byte[] iv = new byte[prp.getBlockSize()];
		//Generate a random IV
		this.random.nextBytes(iv);
		
		//Encrypt the plaintext with the just chosen random IV.
		IVCiphertext cipher = null;
		try {
			cipher =  (IVCiphertext) encrypt(plaintext, iv);
		} catch (IllegalBlockSizeException e) {
			
			e.printStackTrace();
		}
		return cipher;
	}
	
	/**
	 * This function encrypts a plaintext. It lets the system choose the random IV.
	 * @return an IVCiphertext, which contains the IV used and the encrypted data. 
	 */
	public SymmetricCiphertext encrypt(Plaintext plaintext, byte[] iv) throws IllegalBlockSizeException{
		//Check validity of IV's length:
		if(iv.length != prp.getBlockSize()){
			throw new IllegalBlockSizeException("The length of the IV passed is not equal to the block size of current PRP");
		}
		//Each implementing class must write the actual encryption algorithm in "encAlg" function. 
		BasicPlaintext text = (BasicPlaintext)plaintext;
		IVCiphertext cipher =  encAlg(text.getText(),iv);
		return cipher;
	}
	

	//This protected function must be implemented in each concrete class.
	//In CTREnc this function performs the CTR mode of operation.
	//In CBCEnc this function performs the CBC mode of operation.
	protected abstract IVCiphertext encAlg(byte[] plaintext, byte[] iv);

	
}
