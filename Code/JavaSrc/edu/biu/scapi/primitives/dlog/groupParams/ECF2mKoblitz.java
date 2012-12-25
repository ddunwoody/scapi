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
 * Koblitz curve is an extended elliptic curve. 
 * In addition to the regular curve, Koblitz curve also contains the order of the subgroup and cofactor.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECF2mKoblitz extends ECF2mGroupParams{

	private static final long serialVersionUID = -1070828281903801704L;

	private BigInteger n; 	//order of the main subgroup
	ECF2mGroupParams curve; //underlying curve
	
	/**
	 * Constructor that sets the underlying curve and the additional parameters
	 * @param curve the underlying curve
	 * @param n order of the sub group
	 * @param h the cofactor
	 */
	public ECF2mKoblitz(ECF2mGroupParams curve, BigInteger n, BigInteger h){
		this.curve = curve;
		this.n = n;
		this.h = h;
	}
	
	/**
	 * Returns the exponent of the underlying curve
	 * @return m
	 */
	public int getM(){
		return curve.getM();
	}

	/**
	 * Returns the integer <code>k1</code> of the underlying curve where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>.
	 * @return k1 of the underlying curve
	 */
	public int getK1(){
		int k1 = 0;
		if (curve instanceof ECF2mTrinomialBasis)
			k1 = ((ECF2mTrinomialBasis)curve).getK1();
		
		if (curve instanceof ECF2mPentanomialBasis)
			k1 = ((ECF2mPentanomialBasis)curve).getK1();
		
		return k1;
	}
	
	/**
	 * Returns the integer <code>k2</code> of the underlying curve where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>.
	 * @return k2 of the underlying curve
	 */
	public int getK2(){
		int k2 = 0;
		if (curve instanceof ECF2mTrinomialBasis) //trinomial basis has no k2
			k2 = 0;
		
		if (curve instanceof ECF2mPentanomialBasis)
			k2 = ((ECF2mPentanomialBasis)curve).getK2();
		
		return k2;
	}
	
	/**
	 * Returns the integer <code>k3</code> where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>.
	 * @return k3 of the underlying curve
	 */
	public int getK3(){
		int k3 = 0;
		if (curve instanceof ECF2mTrinomialBasis) //trinomial basis has no k2
			k3 = 0;
		
		if (curve instanceof ECF2mPentanomialBasis)
			k3 = ((ECF2mPentanomialBasis)curve).getK3();
		
		return k3;
	}
	
	/**
	 * Returns the order of this group
	 * @return q the group order
	 */
	public BigInteger getQ(){
		return curve.getQ();
	}
	
	/**
	 * Returns the x coordinate of the generator of this group
	 * @return xG the x coordinate of the generator 
	 */
	public BigInteger getXg(){
		return curve.getXg();
	}
	
	/**
	 * Returns the y coordinate of the generator of this group
	 * @return yG the y coordinate of the generator 
	 */
	public BigInteger getYg(){
		return curve.getYg();
	}
	
	/**
	 * Returns the a coefficient of this elliptic curve equation
	 * @return a the a coefficient of this elliptic curve equation
	 */
	public BigInteger getA(){
		return curve.getA();
	}
	
	/**
	 * Returns the b coefficient of this elliptic curve equation
	 * @return b the b coefficient of this elliptic curve equation
	 */
	public BigInteger getB(){
		return curve.getB();
	}
	
	/**
	 * Returns the subgroup order of this group
	 * @return n the subgroup order
	 */
	public BigInteger getSubGroupOrder(){
		return n;
	}
	
	/**
	 * Returns the underlying curve
	 * @return the underlying curve
	 */
	public ECF2mGroupParams getCurve(){
		return curve;
	}

	@Override
	public String toString() {
		return "ECF2mKoblitz [getM()=" + getM() + ", getK1()=" + getK1()
				+ ", getK2()=" + getK2() + ", getK3()=" + getK3() + ", getQ()="
				+ getQ() + ", getXg()=" + getXg() + ", getYg()=" + getYg()
				+ ", getA()=" + getA() + ", getB()=" + getB()
				+ ", getSubGroupOrder()=" + getSubGroupOrder()
				+ ", getCurve()=" + getCurve() + ", getCofactor()="
				+ getCofactor() + ", getClass()=" + getClass()
				+ ", hashCode()=" + hashCode() + ", toString()="
				+ super.toString() + "]";
	}

	
	
	
}
