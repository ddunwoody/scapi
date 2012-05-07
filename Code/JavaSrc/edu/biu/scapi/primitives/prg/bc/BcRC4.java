package edu.biu.scapi.primitives.prg.bc;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.engines.RC4Engine;

import edu.biu.scapi.primitives.prg.RC4;

/**
 * Concrete class of PRF for RC4. This class is a wrapper class for BC implementation of RC4.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public final class BcRC4 extends BcPRG implements RC4{
	
	/**
	 * Passes the RC4Engine of BC to the abstract super class
	 */
	public BcRC4(){
		super(new RC4Engine());
	}
	
	public BcRC4(SecureRandom random){
		super(new RC4Engine(), random);
	}
	
	public BcRC4(String randNumGenAlg) throws NoSuchAlgorithmException {
		
		super(new RC4Engine(),  SecureRandom.getInstance(randNumGenAlg));
	}
	
	public void setKey(SecretKey secretKey) {
		
		//sets the parameters
		super.setKey(secretKey);
		
		//RC4 has a problem in the first 1024 bits. by ignoring these bytes, we bypass this problem.
		byte[] out = new byte[128];
		getPRGBytes(out, 0, 128);
		
	}
	
}