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
	 * @param h the group cofactor
	 */
	public ECFpGroupParams(BigInteger q, BigInteger xG, BigInteger yG, BigInteger p, BigInteger a, BigInteger b, BigInteger h) {
		this.q = q;
		this.xG = xG;
		this.yG = yG;
		this.a = a;
		this.b = b;
		this.p = p;
		this.h = h;
	}
	
	/*
	 * Returns the prime modulus of the group
	 * @return p
	 */
	public BigInteger getP(){
		return p;
	}
}
