package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;

public class ScDSAPrivateKeySpec {

	private BigInteger x;
	
	public ScDSAPrivateKeySpec(BigInteger x){
		this.x = x;
	}
	
	
	public BigInteger getX() {
		
		return x;
	}
}
