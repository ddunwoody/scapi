package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.security.PublicKey;

import edu.biu.scapi.primitives.dlog.GroupElement;

public interface ElGamalPublicKey extends PublicKey {
	
	public GroupElement getH();
}
