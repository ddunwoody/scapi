package edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * Abstract class for RSA PSS signature scheme. This class implements some common functionality of RSA signature scheme.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class RSAPssAbs implements RSABasedSignature{

	protected SecureRandom random;		//Source of randomness
	protected boolean isKeySet;
	protected RSAPublicKey publicKey;
	
	@Override
	public boolean isKeySet() {
		return isKeySet;
	}
	
	/**
	 * Returns the PublicKey of this RSA encryption scheme.
	 * @return the RSAPublicKey
	 * @throws IllegalStateException if no public key was set.
	 */
	public PublicKey getPublicKey(){
		if (!isKeySet()){
			throw new IllegalStateException("no PublicKey was set");
		}
		
		return publicKey;
	}
	
	/**
	 * @return this signature scheme name - "RSA/PSS"
	 */
	@Override
	public String getAlgorithmName() {
		
		return "RSA/PSS";
	}
	
	/**
	 * Generate an RSA key pair using the given parameters.
	 * @param keyParams RSAKeyGenParameterSpec.
	 * @return KeyPair contains keys for this RSAPss object.
	 * @throws InvalidParameterSpecException if keyParams is not instance of RSAKeyGenParameterSpec.
	 */
	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams)
			throws InvalidParameterSpecException {
		
		try {
			//Generates keys using the KeyPairGenerator.
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(keyParams, random);
			return generator.generateKeyPair(); 
		} catch(InvalidAlgorithmParameterException e){
			//Throws the same exception with different message.
			throw new InvalidParameterSpecException("keyParams should be instance of RSAKeyGenParameterSpec");
		} catch (NoSuchAlgorithmException e) {
			//Shouldn't occur since RSA is a valid algorithm.
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * This function is not supported in this class. 
	 * Use generateKey(AlgorithmParameterSpec keyParams) instead.
	 * @throws UnsupportedOperationException
	 */
	@Override
	public KeyPair generateKey() {
		throw new UnsupportedOperationException("To generate keys for this RSAPss use the other generateKey function with RSAKeyGenParameterSpec");
	}

}
