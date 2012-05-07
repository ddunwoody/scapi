package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class ScRabinPublicKeySpec implements KeySpec{
	BigInteger modulus = null;
	private BigInteger quadraticResidueModPrime1 = null; //r
	private BigInteger quadraticResidueModPrime2 = null; //s

	/**
	 * Constructor that accepts the public key parameters and sets them.
	 * @param mod modulus
	 * @param r - quadratic residue mod prime1
	 * @param s - quadratic residue mod prime2
	 */
	public ScRabinPublicKeySpec (BigInteger mod, BigInteger r, BigInteger s) {
		modulus = mod;
		quadraticResidueModPrime1 = r;
		quadraticResidueModPrime2 = s;
	}
	
	/**
	 * @return BigInteger - the modulus
	 */
	public BigInteger getModulus() {
		
		return modulus;
	}
	
	/**
	 * @return BigInteger - QuadraticResidueModPrime1 (r)
	 */
	public BigInteger getQuadraticResidueModPrime1() {
		
		return quadraticResidueModPrime1;
	}

	/**
	 * @return BigInteger - QuadraticResidueModPrime2 (s)
	 */
	public BigInteger getQuadraticResidueModPrime2() {
		
		return quadraticResidueModPrime2;
	}
}
