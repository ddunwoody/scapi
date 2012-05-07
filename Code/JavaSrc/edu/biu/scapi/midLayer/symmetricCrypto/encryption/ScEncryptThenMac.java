package edu.biu.scapi.midLayer.symmetricCrypto.encryption;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.ciphertext.EncMacCiphertext;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
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
	
	private SymmetricEnc encryptor;		//The symmetric encryption object used to perform the encrypt part of encrypt-then-mac algorithm
	private Mac mac;					//The mac object used to perform the authentication part of encrypt-then-mac algorithm
	
	/**
	 * Default constructor
	 * @throws UnInitializedException 
	 */
	public ScEncryptThenMac() throws UnInitializedException{
		this.encryptor = new ScCTREncRandomIV( new BcAES());
		this.mac = new ScCbcMacPrepending(new BcTripleDES());
	}
	
	/**
	 * Constructor that gets an Encryption-Scheme name and a Mac name, creates and sets the underlying respective encryption and mac .
	 * It can also pass the name of a PRNG to obtain SecureRandom for encryption and/or mac
	 * Example of transformation for encName: <p>
	 * 		"CTREncRandomIV(AES, SHA1PRNG)" <p>
	 * Example of transformation for macName: <p>
	 * 		"CBCMacPrepending(TripleDes)" 
	 * @param encName the name of the symmetric encryption algorithm
	 * @param macName the name of the mac 
	 * @throws FactoriesException if the creation of the underlying encryption or mac failed
	 */
	public ScEncryptThenMac(String encName, String macName) throws FactoriesException {
		//Create and set the underlying encryption
		SymmetricEnc enc = SymmetricEncFactory.getInstance().getObject(encName);
		//We need to make sure that the encryption scheme requested is not an authenticated encryption scheme as well,
		//so that we do not enter a loop.
		if(enc instanceof AuthenticatedEnc) {
			throw new IllegalArgumentException("A symmetric encryption that is not of type AuthenticatedEnc is needed");
		}
		this.encryptor = enc;
		//Create and set the underlying mac
		Mac mac = MacFactory.getInstance().getObject(macName);
		this.mac = mac;
	}
	
	/**
	 * Constructor that gets a SymmetricEncryption object and a Mac object and sets them as the underlying respective members. 
	 * @param encryptor the SymmetricEncryption that will be used for the encryption part of this scheme
	 * @param mac the Mac that will be used for the authentication part of this scheme
	 */
	public ScEncryptThenMac(SymmetricEnc encryptor, Mac mac) {
		if(encryptor instanceof AuthenticatedEnc)
			throw new IllegalArgumentException("A symmetric encryption that is not of type AuthenticatedEnc is needed");
		this.encryptor = encryptor;
		this.mac = mac;
	}

	/**
	 * This function supplies the encrypt-then-mac object with a Secret Key.
	 * It checks that the given secretKey is of type AuthenticatedKey. If not throws InvalidKeyException.<p>
	 * It then calls encryptor’s relevant setKey with corresponding key and mac’s relevant setKey with corresponding key.
	 * 
	 * @throws InvalidKeyException if key is not of type EncThenMacKey
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
	 * Checks if this object has been initialized.
	 */
	@Override
	public boolean isKeySet() {
		//If both the underlying encryptor and the underlying mac are initialized then return true.
		//Else, return false
		boolean isKeySet = encryptor.isKeySet() && mac.isKeySet();
		return isKeySet;
	}

	@Override
	public String getAlgorithmName() {
		return "EncryptThenMacWith" + encryptor.getAlgorithmName() + "And" + mac.getAlgorithmName();
	}

	@Override
	public SecretKey generateKey(AlgorithmParameterSpec keySize) throws InvalidParameterSpecException {
		if(!(keySize instanceof AuthEncKeyGenParameterSpec))
			throw new InvalidParameterSpecException("keySize has to be of type AuthEncKeyGenParameterSpec");
		AuthEncKeyGenParameterSpec params = (AuthEncKeyGenParameterSpec) keySize;
		SecretKey encKey = encryptor.generateKey(params.getEncKeySize());
		SecretKey macKey = mac.generateKey(params.getMacKeySize());
		EncThenMacKey key = new EncThenMacKey(encKey, macKey);
		return key;
	}
	
	@Override
	public SecretKey generateKey(int keySize) {
		throw new UnsupportedOperationException("Encrypt then Mac encryption requires a key size for encryption and a key size for mac. " +
				"Use generateKey with AlgorithmParameterSpec");
	}


	@Override
	public SymmetricCiphertext encrypt(Plaintext plaintext) {
		BasicPlaintext text = (BasicPlaintext) plaintext;
		int length = text.getText().length;
		
		SymmetricCiphertext basicCipher = encryptor.encrypt(plaintext);
		byte[] tag = mac.mac(basicCipher.getBytes(), 0, length);
		EncMacCiphertext encMacCipher = new EncMacCiphertext(basicCipher, tag); 
		return (SymmetricCiphertext) encMacCipher;
	}

	@Override
	public SymmetricCiphertext encrypt(Plaintext plaintext, byte[] iv)throws  IllegalBlockSizeException {

		BasicPlaintext text = (BasicPlaintext) plaintext;
		int length = text.getText().length;
		
		SymmetricCiphertext basicCipher = encryptor.encrypt(plaintext, iv);
		byte[] tag = mac.mac(basicCipher.getBytes(), 0, length);
		EncMacCiphertext encMacCipher = new EncMacCiphertext(basicCipher, tag); 
		return (SymmetricCiphertext) encMacCipher;
	}

	@Override
	public Plaintext decrypt(Ciphertext ciphertext) {			
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
