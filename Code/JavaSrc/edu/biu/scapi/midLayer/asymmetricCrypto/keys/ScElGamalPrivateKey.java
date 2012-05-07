package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;

public class ScElGamalPrivateKey implements ElGamalPrivateKey {

	private static final long serialVersionUID = -5215891366473399087L;
	private BigInteger x;
	
	public ScElGamalPrivateKey(BigInteger x){
		this.x = x;
	}
	
	@Override
	public String getAlgorithm() {
		return "ElGamal";
	}

	@Override
	public byte[] getEncoded() {
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}

	public BigInteger getX(){
		return x;
	}
}
