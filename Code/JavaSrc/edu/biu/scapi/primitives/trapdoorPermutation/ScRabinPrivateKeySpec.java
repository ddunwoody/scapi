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
