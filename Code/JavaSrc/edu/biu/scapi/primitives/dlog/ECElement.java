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
 * Marker interface. Every class that implements it, is signed as an elliptic curve point
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface ECElement extends GroupElement{
	
	
	/**
	 * This function returns the x coordinate of the (x,y) point which is an element of a given elliptic curve.
	 * In case of infinity point, returns null.
	 * @return x coordinate of (x,y) point
	 */
	public BigInteger getX();
	
	/**
	 * This function returns the y coordinate of the (x,y) point which is an element of a given elliptic curve.
	 * In case of infinity point, returns null.
	 * @return y coordinate of (x,y) point
	 */
	public BigInteger getY();
	
	/**
	 * Elliptic curve has a unique point called infinity.
	 * In order to know if this object is an infinity point, this function should be called.
	 * @return true if this point is the infinity, false, otherwise.
	 */
	public boolean isInfinity();
	
	
	
	
}
