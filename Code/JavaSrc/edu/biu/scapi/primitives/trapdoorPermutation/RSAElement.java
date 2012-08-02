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
package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.SecureRandom;


/**
 * Concrete class of TPElement for RSA element. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
final class RSAElement implements TPElement{

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
			//drops the element if it bigger then mod(N)-2
		} while(randNumber.compareTo(modN.add(new BigInteger("-2")))>0);
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


}
