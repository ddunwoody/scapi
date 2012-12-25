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


package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class ScRabinPrivateKeySpec implements KeySpec{
	
	private BigInteger modulus = null;		//modulus
	private BigInteger prime1 = null; 		//p, such that p*q=n
	private BigInteger prime2 = null; 		//q, such that p*q=n
	private BigInteger inversePModQ = null; //u

	/**
	 * Constructor that accepts the private key parameters and sets them.
	 * @param mod modulus
	 * @param p - prime1
	 * @param q - prime2
	 * @param u - inverse of prime1 mod prime2
	 */
	public ScRabinPrivateKeySpec (BigInteger mod, BigInteger p, BigInteger q, BigInteger u) {
		modulus = mod;
		prime1  = p;
		prime2 = q; 
		inversePModQ = u;
	}
	
	/**
	 * @return BigInteger - the modulus
	 */
	public BigInteger getModulus() {
		
		return modulus;
	}
	
	public BigInteger getPrime1() {
		return prime1;
	}

	public BigInteger getPrime2() {
		return prime2;
	}

	public BigInteger getInversePModQ() {
		return inversePModQ;
	}
}
