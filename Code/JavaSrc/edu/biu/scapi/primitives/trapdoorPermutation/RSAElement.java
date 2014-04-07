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
import java.security.SecureRandom;


/**
 * Concrete class of TPElement for RSA element. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public final class RSAElement implements TPElement{

	private BigInteger element; // the element value

	/**
	 * Constructor that chooses a random element according to the given modulus.
	 * @param modN the modulus
	 */
	public RSAElement(BigInteger modN) {
		/*
		 * samples a number between 1 to n-1
		 */

		SecureRandom generator = new SecureRandom();

		BigInteger randNumber = null;
		do {
			//samples a random BigInteger with modN.bitLength()+1 bits
			randNumber = new BigInteger(modN.bitLength()+1, generator);
			//drops the element if it's bigger than mod(N)-2
		} while (randNumber.compareTo(modN.add(new BigInteger("-2")))>0);
		//gets a random BigInteger between 1 to modN-1
		randNumber = randNumber.add(new BigInteger("1"));

		//sets it to be the element
		element = randNumber;
	}

	/**
	 * Constructor that gets a modulus and a value. If the value is a valid RSA element according to the modulus, sets it to be the element.
	 * @param modN - the modulus
	 * @param x - the element value
	 * @throws IllegalArgumentException if the element is not legal according the modulus
	 */
	public RSAElement(BigInteger modN, BigInteger x, boolean check) throws IllegalArgumentException{

		if (! check){
			element = x;
		}else {
			/*
			 * checks if the value is valid (between 1 to (mod n) - 1).
			 * if valid - sets it to be the element
			 * if not valid - throws exception 
			 */
			if(((x.compareTo(BigInteger.ZERO))>0) && (x.compareTo(modN)<0)) {
				element = x;
			} else {
				throw new IllegalArgumentException("element out of range");
			}
		}
	}

	/**
	 * Returns the RSA element.
	 * @return the element
	 */
	public BigInteger getElement() {
		return element;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.primitives.trapdoorPermutation.TPElement#generateSendableData()
	 */
	@Override
	public TPElementSendableData generateSendableData() {
		return new TPElementSendableData(element);
	}


}
