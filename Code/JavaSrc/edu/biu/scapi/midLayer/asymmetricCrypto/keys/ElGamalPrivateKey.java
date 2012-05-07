package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;
import java.security.PrivateKey;

public interface ElGamalPrivateKey extends PrivateKey {
	
	public BigInteger getX();
}
