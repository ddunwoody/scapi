package edu.biu.scapi.primitives.hash.bc;

import org.bouncycastle.crypto.digests.SHA1Digest;

import edu.biu.scapi.primitives.hash.SHA1;

/** 
 * Concrete class of cryptographicHash for SHA1. This class wraps BouncyCastle implementation of SHA1.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class BcSHA1 extends BcHash implements SHA1 {
	/** 
	 * Passes the digest SHA1 of BC to the super class which does the hash computation. 
	 */
	public BcSHA1() {
		//passes the digest SHA1 of BC. 
		super(new SHA1Digest());
	}
}