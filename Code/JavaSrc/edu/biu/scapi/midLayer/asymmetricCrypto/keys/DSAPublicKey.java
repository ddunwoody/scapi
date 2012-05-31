package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.security.PublicKey;

import edu.biu.scapi.primitives.dlog.GroupElement;

public interface DSAPublicKey extends PublicKey {

	public GroupElement getY();

}
