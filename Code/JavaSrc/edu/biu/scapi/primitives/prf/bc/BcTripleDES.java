package edu.biu.scapi.primitives.prf.bc;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.engines.DESedeEngine;

import edu.biu.scapi.primitives.prf.TripleDES;

/**
 * Concrete class of prf family for Triple-DES. This class wraps the implementation of Bouncy castle.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class BcTripleDES extends BcPRP implements TripleDES{

	/**
	 * Passes the DesedeEngine of BC to the abstract super class
	 */
	public BcTripleDES() {
		
		super(new DESedeEngine());
	}
	
	/**
	 * Receives random object to use.
	 * Passes it and the DesedeEngine of BC to the abstract super class.
	 * @param random SecureRandom to use
	 */
	public BcTripleDES(SecureRandom random) {
		
		super(new DESedeEngine(), random);
	}
	
	/**
	 * Receives name of random algorithm to use.
	 * Passes it and the DesedeEngine of BC to the abstract super class.
	 * @param randNumGenAlg random algorithm to use
	 */
	public BcTripleDES(String randNumGenAlg) throws NoSuchAlgorithmException {
		
		super(new DESedeEngine(), SecureRandom.getInstance(randNumGenAlg));
	}
	
	/**
	 * initializes this Triple-DES with secret key.
	 * @param secretKey the secret key
	 * @throws InvalidKeyException 
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException {
		int len = secretKey.getEncoded().length;
		//TripleDes key size should be 128/192 bits 
		if(len!=16 && len!=24){
			throw new InvalidKeyException("TripleDes key size should be 128/192 bits long");
		}
		super.setKey(secretKey);
	}

}
