package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class ScElGamalPrivateKeySpec implements KeySpec {
	
	private BigInteger x;
	
	public ScElGamalPrivateKeySpec(BigInteger x){
		this.x = x;
	}
	
	public BigInteger getX(){
		return x;
	}
}
