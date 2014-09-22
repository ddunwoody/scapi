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


package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Parameters for DamgardJurik key generation based on RSA modulus.<p>
 * These parameters will be used to generate a Key Pair for Damgard Jurik based on RSA modulus n such that n = p*q of length k bits.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class DJKeyGenParameterSpec implements AlgorithmParameterSpec {

	private int modulusLength;
	private int certainty;
	
	/**
	 * Default constructor. The values of the RSA modulus length and the certainty are chosen by SCAPI
	 */
	public DJKeyGenParameterSpec(){
		this.modulusLength = 1024;
		this.certainty = 40;
	}
	
	/**
	 * Constructor that lets you set the length of the RSA modulus and the certainty required regarding the primeness of p and q.
	 * 
	 * @param modulusLength
	 * @param certainty
	 */
	public DJKeyGenParameterSpec(int modulusLength, int certainty){
		this.modulusLength = modulusLength;
		this.certainty = certainty;
	}

	public int getModulusLength() {
		return modulusLength;
	}

	public int getCertainty() {
		return certainty;
	}
	
	
}
