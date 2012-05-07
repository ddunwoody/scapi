package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;

/*
 * Elliptic curves over F2m can be constructed with two basis types, trinomial type or pentanomial type.
 * This class manages the trinomial basis.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECF2mTrinomialBasis extends ECF2mGroupParams{

	private int k; //the integer k where x^m + x^k + 1 represents the reduction polynomial f(z)
	
	/*
	 * constructor that sets the parameters
	 * @param q  group order
	 * @param xG x coordinate of the generator point
	 * @param yG y coordinate of the generator point
	 * @param m the exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
	 * @param k the integer <code>k</code> where <code>x<sup>m</sup> + x<sup>k</sup> + 1</code> 
	 * represents the reduction polynomial <code>f(z)</code>.
	 * @param a the a coefficient of the elliptic curve equation
	 * @param b the b coefficient of the elliptic curve equation
	 */
	public ECF2mTrinomialBasis(BigInteger q, BigInteger xG, BigInteger yG, int m, int k, BigInteger a, BigInteger b){
		this.q = q;
		this.xG = xG;
		this.yG = yG;
		this.a = a;
		this.b = b;
		this.m = m;
		this.k = k;
	}
	
	/*
	 * Returns the integer <code>k</code> where <code>x<sup>m</sup> + x<sup>k</sup> + 1</code> 
	 * @return k
	 */
	public int getK1(){
		return k;
	}
}
