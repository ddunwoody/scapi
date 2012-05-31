package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;
import java.security.PrivateKey;

public interface DSAPrivateKey extends PrivateKey {

	public BigInteger getX();

}
