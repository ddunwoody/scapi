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


package edu.biu.scapi.primitives.trapdoorPermutation.cryptopp;

import java.math.BigInteger;


/**
 * Concrete class of TPElement for Rabin element. This class is a wrapper of Crypto++ Integer object.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
final class CryptoPpRabinElement extends CryptoPpTrapdoorElement{
	//native function. This function is implemented in CryptoPpJavaInterface dll using the JNI tool.
	//returns a pointer to a random native integer object
	private native long getPointerToRandomRabinElement(byte[] modN); 
	
	/**
	 * Constructor that chooses a random element according to the given modulus.
	 * @param modN the modulus
	 */
	CryptoPpRabinElement(BigInteger modN) {
		/*
		 * samples a number between 1 to modulus -1 with a square root mod(N)
		 */
		pointerToInteger = getPointerToRandomRabinElement(modN.toByteArray());
	}
		
	/**
	 * Constructor that gets the mod n and a value x to be the element. 
	 * Because the element doesn't contain p and q, we can't check if the value has a square root modN. 
	 * So we can't know if the element is a valid Rabin element. Therefore, we don't do any checks and save 
	 * the value as is. Any trapdoor permutation that uses this element will check validity before using.
	 * @param modN - modulus
	 * @param x - the element value
	 */
	CryptoPpRabinElement(BigInteger modN, BigInteger x) {
		pointerToInteger = getPointerToElement(x.toByteArray());
	}
	
	/**
	 * Constructor that gets a pointer to a native element and sets it as the native element pointer.
	 * We assume that the given long argument is indeed a pointer to a native element.
	 * @param ptr pointer to a native element
	 */
	CryptoPpRabinElement(long ptr) {
		
		pointerToInteger = ptr;
	}
}
