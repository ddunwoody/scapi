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
package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;

/*
 * This class holds the parameters of an elliptic curves Dlog group.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class ECGroupParams extends GroupParams{
	
	protected BigInteger a; //coefficient a of the elliptic curve equation
	protected BigInteger b; //coefficient b of the elliptic curve equation
	protected BigInteger xG; //x coordinate of the generator point
	protected BigInteger yG; //y coordinate of the generator point
	protected BigInteger h;
	/*
	 * Returns coefficient a of the elliptic curves equation
	 * @return coefficient a
	 */
	public BigInteger getA(){
		return a;
	}
	
	/*
	 * Returns coefficient b of the elliptic curves equation
	 * @return coefficient b
	 */
	public BigInteger getB(){
		return b;
	}
	
	/*
	 * Returns the x coordinate of the generator point
	 * @return the x value of the generator point
	 */
	public BigInteger getXg(){
		return xG;
	}
	
	/*
	 * Returns the y coordinate of the generator point
	 * @return the y value of the generator point
	 */
	public BigInteger getYg(){
		return yG;
	}
	
	/*
	 * Returns the cofactor of the group
	 * @return the cofactor of the group
	 */
	public BigInteger getCofactor(){
		return h;
	}
}
