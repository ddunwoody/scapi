/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScDamgardJurikPrivateKey implements DamgardJurikPrivateKey {

	BigInteger t;
	BigInteger dForS1; //Pre-calculated d in the case the s == 1
	
	public ScDamgardJurikPrivateKey(BigInteger t, BigInteger d){
		this.t = t;
		this.dForS1 = d;
	}
	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		return "DamgardJurik";
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPrivateKey#getT()
	 */
	@Override
	public BigInteger getT() {
		return t;
	}
	
	public BigInteger getDForS1(){
		return dForS1;
	}

}
