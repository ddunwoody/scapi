package edu.biu.scapi.midLayer.symmetricCrypto.encryption;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.midLayer.ciphertext.EncMacCiphertext;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.midLayer.symmetricCrypto.keys.AuthEncKeyGenParameterSpec;
import edu.biu.scapi.midLayer.symmetricCrypto.keys.EncThenMacKey;
import edu.biu.scapi.midLayer.symmetricCrypto.mac.Mac;
import edu.biu.scapi.midLayer.symmetricCrypto.mac.ScCbcMacPrepending;
import edu.biu.scapi.primitives.prf.bc.BcAES;
import edu.biu.scapi.primitives.prf.bc.BcTripleDES;
import edu.biu.scapi.tools.Factories.MacFactory;
import edu.biu.scapi.tools.Factories.SymmetricEncFactory;

/**
 * This class implements a type of authenticated encryption: encrypt then mac.<p>
 * The encryption algorithm first encrypts the message and then calculates a mac on the encrypted message.<p>
 * The decrypt algorithm receives an encrypted message and a tag. It first verifies the encrypted message with the tag. If verifies, then it proceeds to decrypt using the underlying
 * decrypt algorithm, if not returns a null response.<p>
 * This encryption scheme achieves Cca2 and NonMalleable security level.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScEncryptThenMac implements AuthenticatedEnc {
	
	private SymmetricEnc encryptor;		//The symmetric encryption object used to perform the encrypt part of encrypt-then-mac algorithm.
	private Mac mac;					//The mac object used to perform the authentication part of encrypt-then-mac algorithm.
	
	/**
	 * Default constructor. Uses default implementations of symmetricEncryption and Mac.
	 */
	public ScEncryptThenMac(){
		this(new ScCTREncRandomIV( new BcAES()), new ScCbcMacPrepending(new BcTripleDES()));
	}
	
	/**
	 * Constructor that gets an Encryption-Scheme name and a Mac name, creates and sets the underlying respective encryption and mac.
	 * It can also pass the name of a PRNG to obtain SecureRandom for encryption and/or mac.
	 * Example of transformation for encName: "CTREncRandomIV(AES, SHA1PRNG)". <p>
	 * Example of transformation for macName: "CBCMacPrepending(TripleDes)". 
	 * @param encName the name of the symmetric encryption algorithm
	 * @param macName the name of the mac 
	 * @throws FactoriesException if the creation of the underlying encryption or mac failed.
	 * @throws IllegalArgumentException if the given encName is a name of an authenticated encryption.
	 */
	public ScEncryptThenMac(String encName, String macName) throws FactoriesException {
		//Creates and set the underlying encryption
		SymmetricEnc enc = SymmetricEncFactory.getInstance().getObject(encName);
		//We need to make sure that the encryption scheme requested is not an authenticated encryption scheme as well,
		//so that we do not enter a loop.
		if(enc instanceof AuthenticatedEnc) {
			throw new IllegalArgumentException("A symmetric encryption that is not of type AuthenticatedEnc is needed");
		}
		this.encryptor = enc;
		//Creates and set the underlying mac
		Mac mac = MacFactory.getInstance().getObject(macName);
		this.mac = mac;
	}
	
	/**
	 * Constructor that gets a SymmetricEncryption object and a Mac object and sets them as the underlying respective members. 
	 * @param encryptor the SymmetricEncryption that will be used for the encryption part of this scheme.
	 * @param mac the Mac that will be used for the authentication part of this scheme.
	 * @throws IllegalArgumentException if the given encName is a name of an authenticated encryption.
	 */
	public ScEncryptThenMac(SymmetricEnc encryptor, Mac mac) {
		if(encryptor instanceof AuthenticatedEnc)
			throw new IllegalArgumentException("A symmetric encryption that is not of type AuthenticatedEnc is needed");
		this.encryptor = encryptor;
		this.mac = mac;
	}

	/**
	 * This function supplies the encrypt-then-mac object with a Secret Key.
	 * It calls encryptor’s relevant setKey with corresponding key and mac’s relevant setKey with corresponding key.
	 * @param secretKey MUST be an instance of EncThenMacKey.
	 * @throws InvalidKeyException if key is not of type EncThenMacKey.
	 */
	@Override
	public void setKey(SecretKey secretKey) throws InvalidKeyException {
		if(!(secretKey instanceof EncThenMacKey))
			throw new InvalidKeyException("This encryption requires a key of type EncThenMacKey");
		EncThenMacKey key =  (EncThenMacKey) secretKey;
		encryptor.setKey(key.getEncryptionKey());
		mac.setKey(key.getMacKey());
	}

	/**
	 * Checks if this object has been initialized with a secret key.
	 */
	@Override
	public boolean isKeySet() {
		//If both the underlying encryptor and the underlying mac are initialized then return true.
		//Else, return false.
		boolean isKeySet = encryptor.isKeySet() && mac.isKeySet();
		return isKeySet;
	}

	/**
	 * Returns the name of this AuthenticatedEnc scheme with the underlying encryption and mac names.
	 */
	@Override
	public String getAlgorithmName() {
		return "EncryptThenMacWith" + encryptor.getAlgorithmName() + "And" + mac.getAlgorithmName();
	}

	/**
	 * Generates a secret key to initialize this authenticated encryption.
	 * @param keyParams algorithmParameterSpec MUST be an instance of AuthEncKeyGenParameterSpec
	 * @return the generated secret key.
	 * @throws InvalidParameterSpecException if the given keyParams is not an instance of AuthEncKeyGenParameterSpec.
	 */
	@Override
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		if(!(keyParams instanceof AuthEncKeyGenParameterSpec))
			throw new InvalidParameterSpecException("keySize has to be of type AuthEncKeyGenParameterSpec");
		AuthEncKeyGenParameterSpec params = (AuthEncKeyGenParameterSpec) keyParams;
		SecretKey encKey = encryptor.generateKey(params.getEncKeySize());
		SecretKey macKey = mac.generateKey(params.getMacKeySize());
		EncThenMacKey key = new EncThenMacKey(encKey, macKey);
		return key;
	}
	
	/**
	 * This function is not supported in the encryption scheme. Use the generateKey with AuthEncKeyGenParameterSpec.
	 * @throws UnsupportedOperationException
	 */
	@Override
	public SecretKey generateKey(int keySize) {
		throw new UnsupportedOperationException("Encrypt then Mac encryption requires a key size for encryption and a key size for mac. " +
				"Use generateKey with AlgorithmParameterSpec");
	}

	/**
	 * Encrypts a plaintext. 
	 * @param plaintext.
	 * @return a SymmetricCiphertext, which contains the basic cipher and the tag.
	 * @throws IllegalStateException if no secret key was set.
	 * @throws IllegalArgumentException if the given plaintext does not match the underlying encryption type.
	 */
	@Override
	public SymmetricCiphertext encrypt(Plaintext plaintext) {
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		
		SymmetricCiphertext basicCipher = encryptor.encrypt(plaintext);
		byte[] tag = mac.mac(basicCipher.getBytes(), 0, basicCipher.getBytes().length);
		
		return new EncMacCiphertext(basicCipher, tag); 
	}

	/**
	 * This function encrypts a plaintext. 
	 * @param plaintext.
	 * @param IV random bytes to use in the encryption pf the message.
	 * @return an IVCiphertext, which contains the IV used and the encrypted data. 
	 * @throws IllegalStateException if no secret key was set.
	 * @throws IllegalArgumentException if the given plaintext does not match the underlying encryption scheme.
	 * @throws IllegalBlockSizeException if the given IV length is not as the block size.
	 */
	@Override
	public SymmetricCiphertext encrypt(Plaintext plaintext, byte[] iv)throws  IllegalBlockSizeException {
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		
		SymmetricCiphertext basicCipher = encryptor.encrypt(plaintext, iv);
		byte[] tag = mac.mac(basicCipher.getBytes(), 0, basicCipher.getBytes().length);
		
		return new EncMacCiphertext(basicCipher, tag); 
	}

	/**
	 * This function performs the decryption of a ciphertext returning the corresponding decrypted plaintext.
	 * @param ciphertext The Ciphertext to decrypt. MUST be an instance of EncMacCiphertext.
	 * @return the decrypted plaintext.
	 * @throws IllegalArgumentException if the given ciphertext is not an instance of EncMacCiphertext.
	 * @throws IllegalStateException if no secret key was set.
	 */
	@Override
	public Plaintext decrypt(SymmetricCiphertext ciphertext) {			
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		
		if(! (ciphertext instanceof EncMacCiphertext) )
			throw new IllegalArgumentException("The ciphertext to decrypt has to be of type EncMacCiphertext");
		
		EncMacCiphertext encMacCipher = (EncMacCiphertext) ciphertext;
		boolean isVerified = mac.verify(encMacCipher.getBytes(), 0, encMacCipher.getLength(), encMacCipher.getTag());
		
		if(!isVerified){
			return null;
		}
		
		//Now that the message has been verified we can decrypt it:
		return encryptor.decrypt(encMacCipher.getCipher());
	}
}
