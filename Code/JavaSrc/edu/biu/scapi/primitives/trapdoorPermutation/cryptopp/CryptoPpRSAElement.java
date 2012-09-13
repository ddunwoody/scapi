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
