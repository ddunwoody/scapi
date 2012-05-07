/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScCramerShoupPrivateKey implements CramerShoupPrivateKey {

	private static final long serialVersionUID = -646494149973549436L;
	
	private BigInteger x1;
	private BigInteger x2;
	private BigInteger y1;
	private BigInteger y2;
	private BigInteger z;
	
	/**
	 * 
	 */
	public ScCramerShoupPrivateKey(BigInteger x1, BigInteger x2, BigInteger y1,
			BigInteger y2, BigInteger z) {
		super();
		this.x1 = x1;
		this.x2 = x2;
		this.y1 = y1;
		this.y2 = y2;
		this.z = z;
	}

	
	
	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		
		return "CramerShoup";
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		return null;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		return null;
	}

	@Override
	public BigInteger getPrivateExp1() {
		return x1;
	}

	@Override
	public BigInteger getPrivateExp2() {
		return x2;
	}

	@Override
	public BigInteger getPrivateExp3() {
		return y1;
	}

	@Override
	public BigInteger getPrivateExp4() {
		return y2;
	}

	@Override
	public BigInteger getPrivateExp5() {
		return z;
	}

}
