package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class ScRabinPrivateKeySpec implements KeySpec{
	
	private BigInteger modulus = null;		//modulus
	private BigInteger prime1 = null; 		//p, such that p*q=n
	private BigInteger prime2 = null; 		//q, such that p*q=n
	private BigInteger inversePModQ = null; //u

	/**
	 * Constructor that accepts the private key parameters and sets them.
	 * @param mod modulus
	 * @param p - prime1
	 * @param q - prime2
	 * @param u - inverse of prime1 mod prime2
	 */
	public ScRabinPrivateKeySpec (BigInteger mod, BigInteger p, BigInteger q, BigInteger u) {
		modulus = mod;
		prime1  = p;
		prime2 = q; 
		inversePModQ = u;
	}
	
	/**
	 * @return BigInteger - the modulus
	 */
	public BigInteger getModulus() {
		
		return modulus;
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
