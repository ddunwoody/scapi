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
 * This class holds the parameters of an Elliptic curve over Zp.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECFpGroupParams extends ECGroupParams{

	private static final long serialVersionUID = -5003549154325155956L;

	private BigInteger p; //modulus 
	
	/**
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
	
	/**
	 * Returns the prime modulus of the group
	 * @return p
	 */
	public BigInteger getP(){
		return p;
	}

	@Override
	public String toString() {
		return "ECFpGroupParams [p=" + p + ", /na=" + a + ", /nb=" + b + ", /nxG=" + xG + ", /nyG=" + yG + ", /nh=" + h + ", /nq=" + q + "]";
	}
	
	
}
