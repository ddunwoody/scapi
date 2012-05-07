package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class ScCramerShoupPrivateKeySpec implements KeySpec {
	private BigInteger x1;
	private BigInteger x2;
	private BigInteger y1;
	private BigInteger y2;
	private BigInteger z;
	
	public ScCramerShoupPrivateKeySpec(BigInteger x1, BigInteger x2,
			BigInteger y1, BigInteger y2, BigInteger z) {
		super();
		this.x1 = x1;
		this.x2 = x2;
		this.y1 = y1;
		this.y2 = y2;
		this.z = z;
	}
	public BigInteger getX1() {
		return x1;
	}
	public BigInteger getX2() {
		return x2;
	}
	public BigInteger getY1() {
		return y1;
	}
	public BigInteger getY2() {
		return y2;
	}
	public BigInteger getZ() {
		return z;
	}
	
	
}
