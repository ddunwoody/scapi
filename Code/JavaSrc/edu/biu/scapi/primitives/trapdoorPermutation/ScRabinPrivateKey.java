package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;


/**
 * Concrete class of RabinPrivateKey
 *
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public class ScRabinPrivateKey extends ScRabinKey implements RabinPrivateKey {

	private BigInteger prime1 = null; 		//p, such that p*q=n
	private BigInteger prime2 = null; 		//q, such that p*q=n
	private BigInteger inversePModQ = null; //u

	
	private static final long serialVersionUID = 1L;

	/**
	 * Constructor that accepts the private key parameters and sets them.
	 * @param mod modulus
	 * @param p - prime1
	 * @param q - prime2
	 * @param u - inverse of prime1 mod prime2
	 */
	public ScRabinPrivateKey (BigInteger mod, BigInteger p, BigInteger q, BigInteger u) {
		modulus = mod;
		prime1  = p;
		prime2 = q; 
		inversePModQ = u;
	}
	
	/**
	 * @return the algorithm name - Rabin
	 */
	public String getAlgorithm() {
		
		return "Rabin";
	}

	/**
	 * @return the encoded key
	 */
	public byte[] getEncoded() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * @return the format of the encoding
	 */
	public String getFormat() {
		// TODO Auto-generated method stub
		return null;
	}

	public BigInteger getPrime1() {
		return prime1;
	}

	public BigInteger getPrime2() {
		return prime2;
	}

	public BigInteger getInversePModQ() {
		return inversePModQ;
	}

}