package edu.biu.scapi.primitives.hash.bc;

import org.bouncycastle.crypto.digests.SHA512Digest;

import edu.biu.scapi.primitives.hash.SHA512;

/** 
 * Concrete class of cryptographicHash for SHA512. This class wraps BouncyCastle implementation of SHA512.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class BcSHA512 extends BcHash implements SHA512 {

	/**
	 * Passes the digest SHA512 of BC to the super class which does the hash computation. 
	 */
	public BcSHA512() {
		//passes the digest SHA512 of BC. 
		super(new SHA512Digest());
	}
}
