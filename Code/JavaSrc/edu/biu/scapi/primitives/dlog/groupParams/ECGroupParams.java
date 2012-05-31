package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;

/*
 * This class holds the parameters of an elliptic curves Dlog group.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class ECGroupParams extends GroupParams{
	
	protected BigInteger a; //coefficient a of the elliptic curve equation
	protected BigInteger b; //coefficient b of the elliptic curve equation
	protected BigInteger xG; //x coordinate of the generator point
	protected BigInteger yG; //y coordinate of the generator point
	protected BigInteger h;
	/*
	 * Returns coefficient a of the elliptic curves equation
	 * @return coefficient a
	 */
	public BigInteger getA(){
		return a;
	}
	
	/*
	 * Returns coefficient b of the elliptic curves equation
	 * @return coefficient b
	 */
	public BigInteger getB(){
		return b;
	}
	
	/*
	 * Returns the x coordinate of the generator point
	 * @return the x value of the generator point
	 */
	public BigInteger getXg(){
		return xG;
	}
	
	/*
	 * Returns the y coordinate of the generator point
	 * @return the y value of the generator point
	 */
	public BigInteger getYg(){
		return yG;
	}
	
	/*
	 * Returns the cofactor of the group
	 * @return the cofactor of the group
	 */
	public BigInteger getCofactor(){
		return h;
	}
}
