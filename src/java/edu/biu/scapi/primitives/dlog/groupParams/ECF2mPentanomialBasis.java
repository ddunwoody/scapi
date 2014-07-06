/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;

/**
 * Elliptic curves over F2m can be constructed with two basis types, trinomial type or pentanomial type.
 * This class manages the pentanomial basis.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECF2mPentanomialBasis extends ECF2mGroupParams{

	private static final long serialVersionUID = -2591866669252876049L;

	// x^m + x^k3 + x^k2 + x^k1 + 1 represents the reduction polynomial f(z)
	private int k1; 
	private int k2;
	private int k3;
	
	
	/**
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
	
	/**
	 * Returns the integer <code>k1</code> where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>.
     * @return k1
     */
	public int getK1(){
		return k1;
	}
	
	/**
	 * Returns the integer <code>k2</code> where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>.
     * @return k2
     */
	public int getK2(){
		return k2;
	}
	
	/** 
	 * Returns the integer <code>k3</code> where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>.
     * @return k3
     */
	public int getK3(){
		return k3;
	}

	@Override
	public String toString() {
		return "ECF2mPentanomialBasis [k1=" + k1 + ", k2=" + k2 + ", k3=" + k3
				+ ", m=" + m + ", a=" + a + ", b=" + b + ", xG=" + xG + ", yG="
				+ yG + ", h=" + h + ", q=" + q + "]";
	}

	

	
}
