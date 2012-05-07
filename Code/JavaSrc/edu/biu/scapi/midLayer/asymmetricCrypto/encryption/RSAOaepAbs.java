package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;

public abstract class RSAOaepAbs implements RSAOaep {

	protected SecureRandom random;					//source of randomness
	protected boolean isKeySet;
	
	
	@Override
	public boolean isKeySet() {
		return isKeySet();
	}

	/**
	 * @return the name of this Asymmetric encryption - "RSAOAEP"
	 */
	@Override
	public String getAlgorithmName() {
		return "RSA/OAEP";
	}



	/**
	 * Generates a KeyPair contains set of RSAPublicKEy and RSAPrivateKey using default source of randomness.
	 * @param keyParams RSAPssParameterSpec
	 * @return KeyPair contains keys for this RSAPss object
	 * @throws InvalidParameterSpecException if keyParams is not instance of RSAPssParameterSpec
	 */
	@Override
	public KeyPair generateKey() {
		throw new UnsupportedOperationException();
	}

	
	/**
	 * Generate an RSA key pair using the given source of randomness.
	 * @param keyParams RSAPssParameterSpec
	 * @return KeyPair contains keys for this RSAPss object
	 * @throws InvalidParameterSpecException if keyParams is not instance of RSAPssParameterSpec
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
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

}
