package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;

/*
 * Elliptic curves over F2m can be constructed with two basis types, trinomial type or pentanomial type.
 * This class manages the pentanomial basis.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECF2mPentanomialBasis extends ECF2mGroupParams{

	// x^m + x^k3 + x^k2 + x^k1 + 1 represents the reduction polynomial f(z)
	private int k1; 
	private int k2;
	private int k3;
	
	
	/*
	 * Sets the parameters
	 * @param q the group order
	 * @param xG x coordinate of the generator point
	 * @param yG y coordinate of the generator point
	 * @param m  the exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
     * @param k1 the integer <code>k1</code> where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>.
     * @param k2 the integer <code>k2</code> where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>.
     * @param k3 the integer <code>k3</code> where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>.
	 * @param a the a coefficient of the elliptic curve equation
	 * @param b the b coefficient of the elliptic curve equation
	 * @param h the group cofactor
	 */
	public ECF2mPentanomialBasis(BigInteger q, BigInteger xG, BigInteger yG, int m, int k1, int k2, int k3, BigInteger a, BigInteger b, BigInteger h){
		this.q = q;
		this.xG = xG;
		this.yG = yG;
		this.a = a;
		this.b = b;
		this.m = m;
		this.k1 = k1;
		this.k2 = k2;
		this.k3 = k3;
		this.h = h;
	}
	
	/*
	 * Returns the integer <code>k1</code> where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>.
     * @return k1
     */
	public int getK1(){
		return k1;
	}
	
	/* Returns the integer <code>k2</code> where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>.
     * @return k2
     */
	public int getK2(){
		return k2;
	}
	
	/* Returns the integer <code>k3</code> where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>.
     * @return k3
     */
	public int getK3(){
		return k3;
	}

	

	
}
