package edu.biu.scapi.primitives.dlog.groupParams;


import java.math.BigInteger;
/*
 * This class holds the parameters of an Elliptic curve over Zp.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECFpGroupParams extends ECGroupParams{

	private BigInteger p; //modulus 
	
	/*
	 * Sets the order, generator and coefficients parameters
	 * @param q group order
	 * @param xG x coordinate of the generator point
	 * @param yG y coordinate of the generator point
	 * @param p group modulus
	 * @param a the a coefficient of the elliptic curve equation
	 * @param b the b coefficient of the elliptic curve equation
	 */
	public ECFpGroupParams(BigInteger q, BigInteger xG, BigInteger yG, BigInteger p, BigInteger a, BigInteger b) {
		this.q = q;
		this.xG = xG;
		this.yG = yG;
		this.a = a;
		this.b = b;
		this.p = p;
	}
	
	/*
	 * Returns the prime modulus of the group
	 * @return p
	 */
	public BigInteger getP(){
		return p;
	}
}
