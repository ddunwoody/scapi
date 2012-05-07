package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.security.KeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;

import edu.biu.scapi.exceptions.ScapiRuntimeException;
import edu.biu.scapi.midLayer.ciphertext.BasicAsymCiphertext;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;

/**
 * This class performs the RSA-OAEP encryption and decryption scheme.
 * By definition, this encryption scheme is CCA-secure.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class BcRSAOaep extends RSAOaepAbs {
	
	private OAEPEncoding bcBlockCipher;				//the underlying BC OAEP encoding
	private CipherParameters privateParameters;		//parameters contains the private key and the random
	private CipherParameters publicParameters;		//parameters contains the public key and the random
	private boolean forEncryption = true;
	private RSAPrivateKey privateKey;				
	private RSAPublicKey publicKey;					
	

	
	/**
	 * Default constructor
	 */
	public BcRSAOaep(){
		this(new SecureRandom());
	}
	
	/**
	 * Constructor that lets the user choose the source of randomness
	 * @param random
	 */
	public BcRSAOaep(SecureRandom random){
		this.random = random;
		//creates the OAEP encoding with RSABlindedEngine of BC
		this.bcBlockCipher = new OAEPEncoding(new RSABlindedEngine());

	}
	/**
	 * Set this RSAOAEP encryption scheme with a Public/Private key pair.
	 * In thiscase the user can encrypt and decrypt messages.
	 * @param publicKey should be RSAPublicKey
	 * @param privateKey should be RSAPrivateKey
	 */
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey) {
		//key should be RSA keys
		if(!(publicKey instanceof RSAPublicKey)){
			throw new IllegalArgumentException("keys should be instances of RSA keys");
		}
		if(privateKey!= null && !(privateKey instanceof RSAPrivateKey)){
				throw new IllegalArgumentException("keys should be instances of RSA keys");
		}
		//set the parameters
		this.publicKey = (RSAPublicKey) publicKey;
		this.privateKey = (RSAPrivateKey) privateKey; //What happens if null?
				
		//create BC objects and initialize them
		initBCCipher();
		isKeySet = true;
	}



	/**
	 * Set this RSAOAEP encryption scheme only with public key.
	 * In this case the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be RSAPublicKey
	 */
	@Override
	public void setKey(PublicKey publicKey) {
		setKey(publicKey, null);
	}
	/**
	 * Creates BC OAEPEncoding with BC RSABlindedEngine, translate the keys and random to BC CipherParameters
	 * and initialize BC object in encrypt mode.
	 * In order to decript, the decrypt function initialize them again to decrypt mode.
	 */
	private void initBCCipher(){
		
		//translate the keys and random to BC parameters
		privateParameters = BCParametersTranslator.getInstance().translateParameter(privateKey, random);
		publicParameters = BCParametersTranslator.getInstance().translateParameter(publicKey, random);
		//initialize the OAEP object with the cipherPerameters and for encryption
		bcBlockCipher.init(forEncryption, publicParameters);
	}
	
	
	/**
	 * Encrypts the given plaintext according to the RSAOAEP algorithm using BC OAEPEncoding.
	 * @param plaintext the plaintext to encrypt
	 * @return Ciphertext contains the encrypted plaintext
	 */
	@Override
	public Ciphertext encrypt(Plaintext plaintext) {		
		//if the underlying BC object used to the encryption is in decrypt mode - change it
		//TODO make sure that this mechanism covers all possibilities.
		if (!forEncryption){
			forEncryption = true;
			bcBlockCipher.init(forEncryption, publicParameters);
		}
		
		byte[] plaintextBytes = ((BasicPlaintext) plaintext).getText(); //get the plaintext bytes
		int inputBlockSize = bcBlockCipher.getInputBlockSize();
		
		//calculate the number of whole blocks
		//int numberBlocksInCipher = plaintextBytes.length / inputBlockSize;
		//int remainder = plaintextBytes.length % inputBlockSize;
		
		byte[] ciphertext;
		try {
			//encrypt block using BC OAEP object
			ciphertext = bcBlockCipher.encodeBlock(plaintextBytes, 0, plaintextBytes.length);
		} catch (InvalidCipherTextException e) {
			throw new ScapiRuntimeException(e.getMessage());
		}

		//return a ciphertext with the encrypted plaintext
		return new BasicAsymCiphertext(ciphertext);
	}

	/**
	 * Decrypts the given ciphertext according to the RSAOAEP algorithm using BC OAEPEncoding.
	 * @param cipher the ciphertext to decrypt
	 * @return Plaintext contains the decrypted ciphertext
	 * @throws KeyException 
	 */
	@Override
	public Plaintext decrypt(Ciphertext cipher) throws KeyException {
		//if there is no private key can not decrypt, throw exception
		if (privateKey == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//cipher must be of type BasicAsymCiphertext
		if (!(cipher instanceof BasicAsymCiphertext)){
			throw new IllegalArgumentException("The ciphertext has to be of type BasicAsymCiphertext");
		}
		//if the underlying BC object used to the decryption is in encrypt mode - change it
		//TODO make sure that this mechanism covers all possibilities.
		if (forEncryption){
			forEncryption = false;
			bcBlockCipher.init(forEncryption, privateParameters);
		}
		
		byte[] ciphertext = ((BasicAsymCiphertext) cipher).getBytes();

		byte[] plaintext;
		try {
			//decrypt block using BC OAEP object
			plaintext = bcBlockCipher.decodeBlock(ciphertext, 0, ciphertext.length);
		} catch (InvalidCipherTextException e) {
			throw new ScapiRuntimeException(e.getMessage());
		}
		//return a plaintext with the decrypted ciphertext
		return new BasicPlaintext(plaintext);
	}
	
}
