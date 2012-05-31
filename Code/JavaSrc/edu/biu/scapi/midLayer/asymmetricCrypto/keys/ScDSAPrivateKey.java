package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;

public class ScDSAPrivateKey implements DSAPrivateKey{

	/**
	 * 
	 */
	private static final long serialVersionUID = -8583117475560439512L;
	private BigInteger x;
	
	public ScDSAPrivateKey(BigInteger x){
		this.x = x;
	}
	
	@Override
	public BigInteger getX() {
		
		return x;
	}
	
	@Override
	public String getAlgorithm() {
		
		return null;
	}

	@Override
	public byte[] getEncoded() {
		
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}

	

}
