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
