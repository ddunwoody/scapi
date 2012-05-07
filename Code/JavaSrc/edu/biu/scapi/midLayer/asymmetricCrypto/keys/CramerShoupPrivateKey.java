package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;
import java.security.PrivateKey;

public interface CramerShoupPrivateKey extends PrivateKey {
	BigInteger getPrivateExp1();
	BigInteger getPrivateExp2();
	BigInteger getPrivateExp3();
	BigInteger getPrivateExp4();
	BigInteger getPrivateExp5();
}
