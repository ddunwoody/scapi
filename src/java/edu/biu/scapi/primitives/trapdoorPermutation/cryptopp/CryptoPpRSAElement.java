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
 * Concrete class of TPElement for RSA element. This class is a wrapper of Crypto++ Integer object.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
final class CryptoPpRSAElement extends CryptoPpTrapdoorElement{
	//native function. This function is implemented in CryptoPpJavaInterface dll using the JNI tool.
	//returns a pointer to a random native integer object
	private native long getPointerToRandomRSAElement(byte[] modN);
	
	/**
	 * Constructor that chooses a random element according to the given modulus.
	 * @param modN the modulus
	 */
	CryptoPpRSAElement(BigInteger modN) {
		/*
		 * calls a native function that samples a random number between 1 to mondN-1 and returns its pointer.
		 * sets the pointer to be the element pointer
		 */
		pointerToInteger = getPointerToRandomRSAElement (modN.toByteArray());
	}
		
	/**
	 * Constructor that gets a modulus and a value. It sets the x value as the element. If check is true, it checks that the x value is a valid RSA element according to the modulus.
	 * @param modN - the modulus
	 * @param x - the element value
	 * @param check if true, check if x is valid for modulus
	 * 				else, do not check and set x as is
	 * @throws IllegalArgumentException if the element is not legal according to the modulus and check was requested
	 */
	CryptoPpRSAElement(BigInteger modN, BigInteger x, boolean check) throws IllegalArgumentException{
		if( !check){
			pointerToInteger = getPointerToElement(x.toByteArray());
		}else {
		/*checks if the value is valid (between 1 to (modN) - 1 ).
		  if valid - calls a native function that returns pointer and sets it to be the element pointer
		  if not valid - throws exception */
		if(((x.compareTo(BigInteger.ZERO))>0) && (x.compareTo(modN)<0)) {
				pointerToInteger = getPointerToElement(x.toByteArray());
		} else {
			throw new IllegalArgumentException("element out of range");
		}
		}
	}
	
	
	/**
	 * Constructor that gets a pointer to a native element and sets it as the native element pointer.
	 * We assume that the given long argument is indeed a pointer to a native element.
	 * @param ptr pointer to a native element
	 */
	CryptoPpRSAElement(long ptr) {
		
		pointerToInteger = ptr;
	}
}
