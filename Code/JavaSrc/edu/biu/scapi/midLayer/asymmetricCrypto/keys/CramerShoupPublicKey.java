package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.security.PublicKey;

import edu.biu.scapi.primitives.dlog.GroupElement;

public interface CramerShoupPublicKey extends PublicKey {
	GroupElement getC();
	GroupElement getD();
	GroupElement getH();
	GroupElement getGenerator1();
	GroupElement getGenerator2();
}
