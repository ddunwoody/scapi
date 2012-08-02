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


/**
 * Concrete class of RabinPublicKey
 *
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public class ScRabinPublicKey extends ScRabinKey implements RabinPublicKey {
	
	private static final long serialVersionUID = 1L;
	
	private BigInteger quadraticResidueModPrime1 = null; //r
	private BigInteger quadraticResidueModPrime2 = null; //s

	/**
	 * Constructor that accepts the public key parameters and sets them.
	 * @param mod modulus
	 * @param r - quadratic residue mod prime1
	 * @param s - quadratic residue mod prime2
	 */
	public ScRabinPublicKey (BigInteger mod, BigInteger r, BigInteger s) {
		modulus = mod;
		quadraticResidueModPrime1 = r;
		quadraticResidueModPrime2 = s;
	}

	/**
	 * @return the algorithm name - Rabin
	 */
	public String getAlgorithm() {
		
		return "Rabin";
	}

	/**
	 * @return the encoded key
	 */
	public byte[] getEncoded() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * @return the format of the encoding
	 */
	public String getFormat() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * @return BigInteger - QuadraticResidueModPrime1 (r)
	 */
	public BigInteger getQuadraticResidueModPrime1() {
		
		return quadraticResidueModPrime1;
	}

	/**
	 * @return BigInteger - QuadraticResidueModPrime2 (s)
	 */
	public BigInteger getQuadraticResidueModPrime2() {
		
		return quadraticResidueModPrime2;
	}

}
