package edu.biu.scapi.primitives.hash.bc;

import org.bouncycastle.crypto.digests.SHA256Digest;

import edu.biu.scapi.primitives.hash.SHA256;

/** 
 * Concrete class of cryptographicHash for SHA256. This class wraps BouncyCastle implementation of SHA256.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class BcSHA256 extends BcHash implements SHA256 {

	/** 
	 * Passes the digest SHA256 of BC to the super class which does the hash computation. 
	 */
	public BcSHA256() {
		//passes the digest SHA256 of BC. 
		super(new SHA256Digest());
	}
}
