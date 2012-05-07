package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;
/**
 * This class holds the parameters of a Dlog group over Zp*.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ZpGroupParams extends GroupParams{

	private BigInteger p; //modulus
	private BigInteger xG; //generator value
	
	/**
	 * constructor that sets the order, generator and modulus
	 * @param q - order of the group
	 * @param xG - generator of the group
	 * @param p - modulus of the group
	 */
	public ZpGroupParams(BigInteger q, BigInteger xG, BigInteger p) {
		this.q = q;
		
		this.xG = xG;
		
		this.p = p;
	}
	
	/**
	 * Returns the prime modulus of the group
	 * @return p
	 */
	public BigInteger getP(){
		return p;
	}
	
	/**
	 * Returns the generator of the group
	 * @return xG - the generator value
	 */
	public BigInteger getXg(){
		return xG;
	}
}
