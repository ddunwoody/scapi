package edu.biu.scapi.primitives.prf.bc;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.engines.AESEngine;

import edu.biu.scapi.primitives.prf.AES;

/**
 * Concrete class of prf family for AES. This class wraps the implementation of Bouncy castle.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public final class BcAES extends BcPRP implements AES{

	/**
	 * Passes the AESEngine of BC to the abstract super class
	 */
	public BcAES() {
		super(new AESEngine());
		
	}
	
	/**
	 * Receives random object to use.
	 * Passes it and the DesedeEngine of BC to the abstract super class.
	 * @param random SecureRandom to use
	 */
	public BcAES(SecureRandom random) {
		super(new AESEngine(), random);
	}
	
	/**
	 * Receives name of random algorithm to use.
	 * Passes it and the AESEngine of BC to the abstract super class.
	 * @param randNumGenAlg random algorithm to use
	 * @throws NoSuchAlgorithmException 
	 */
	public BcAES(String randNumGenAlg) throws NoSuchAlgorithmException {
		super(new AESEngine(), SecureRandom.getInstance(randNumGenAlg));
		
	}

	/**
	 * initializes this AES with secret key.
	 * @param secretKey the secret key
	 * @throws InvalidKeyException 
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException {
		int len = secretKey.getEncoded().length;
		//AES key size should be 128/192/256 bits long
		if(len!=16 && len!=24 && len!=32){
			throw new InvalidKeyException("AES key size should be 128/192/256 bits long");
		}
		super.setKey(secretKey);
	}
	
}
