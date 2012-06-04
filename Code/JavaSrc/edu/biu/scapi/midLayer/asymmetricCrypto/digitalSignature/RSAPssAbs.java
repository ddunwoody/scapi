package edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * General interface for RSA PSS signature scheme. Every concrete implementation of RSA PSS signature should implement this interface.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class RSAPssAbs implements RSABasedSignature{

	protected SecureRandom random;		//source of randomness
	protected boolean isKeySet = false;
	
	
	@Override
	public boolean isKeySet() {
		return isKeySet();
	}
	
	/**
	 * @return this signature scheme name - "RSA/PSS"
	 */
	@Override
	public String getAlgorithmName() {
		
		return "RSA/PSS";
	}
	
	/**
	 * Generate an RSA key pair using the given source of randomness.
	 * @param keyParams RSAKeyGenParameterSpec
	 * @return KeyPair contains keys for this RSAPss object
	 * @throws InvalidParameterSpecException if keyParams is not instance of RSAKeyGenParameterSpec
	 */
	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams)
			throws InvalidParameterSpecException {
		//if keyParams is not the expected, throw exception
		if (!(keyParams instanceof RSAKeyGenParameterSpec)){
			throw new InvalidParameterSpecException("keyParams should be instance of RSAKeyGenParameterSpec");
		}
		
		try {
			//generates keys using the KeyPairGenerator
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(keyParams, random);
			return generator.generateKeyPair(); 
		} catch(InvalidAlgorithmParameterException e){
			//shouldn't occur since the parameterSpec is valid for RSA
		} catch (NoSuchAlgorithmException e) {
			//shouldn't occur since RSA is a valid algorithm
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * This function is not supported in this class. 
	 * Use generateKey(AlgorithmParameterSpec keyParams) instead.
	 */
	@Override
	public KeyPair generateKey() {
		throw new UnsupportedOperationException("To generate keys for this RSAPss use the other generateKey function with RSAKeyGenParameterSpec");
	}

}
