/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
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
