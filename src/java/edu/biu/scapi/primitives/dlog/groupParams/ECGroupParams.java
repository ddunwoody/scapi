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
 * This class holds the parameters of an elliptic curves Dlog group.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class ECGroupParams extends GroupParams{
	
	private static final long serialVersionUID = 7442260005331440764L;
	
	protected BigInteger a; //coefficient a of the elliptic curve equation
	protected BigInteger b; //coefficient b of the elliptic curve equation
	protected BigInteger xG; //x coordinate of the generator point
	protected BigInteger yG; //y coordinate of the generator point
	protected BigInteger h;
	/**
	 * Returns coefficient a of the elliptic curves equation
	 * @return coefficient a
	 */
	public BigInteger getA(){
		return a;
	}
	
	/**
	 * Returns coefficient b of the elliptic curves equation
	 * @return coefficient b
	 */
	public BigInteger getB(){
		return b;
	}
	
	/**
	 * Returns the x coordinate of the generator point
	 * @return the x value of the generator point
	 */
	public BigInteger getXg(){
		return xG;
	}
	
	/**
	 * Returns the y coordinate of the generator point
	 * @return the y value of the generator point
	 */
	public BigInteger getYg(){
		return yG;
	}
	
	/**
	 * Returns the cofactor of the group
	 * @return the cofactor of the group
	 */
	public BigInteger getCofactor(){
		return h;
	}
}
