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
package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;


/**
 * Marker interface. Every class that implements it is signed as elliptic curve.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface DlogEllipticCurve extends DlogGroup {

	/**
	 * Creates a point with the given x,y values 
	 * @param x
	 * @param y
	 * @return the created ECPoint (x,y)
	 */
	public ECElement generateElement(BigInteger x, BigInteger y) throws IllegalArgumentException;
	
	/**
	 * 
	 * @return the infinity point of this dlog group
	 */
	public ECElement getInfinity();

	/**
	 * 
	 * @return the name of the curve. For example - P-192.
	 */
	public String getCurveName();

	/**
	 * 
	 * @return the properties file where the curves are defined.
	 */
	public String getFileName();
}
