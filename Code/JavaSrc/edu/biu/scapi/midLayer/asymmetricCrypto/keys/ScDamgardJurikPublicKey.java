/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScDamgardJurikPublicKey implements DamgardJurikPublicKey {

	BigInteger modulus;
	public ScDamgardJurikPublicKey(BigInteger modulus){
		this.modulus = modulus;
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
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey#getModulus()
	 */
	@Override
	public BigInteger getModulus() {
		return modulus;
	}

}
