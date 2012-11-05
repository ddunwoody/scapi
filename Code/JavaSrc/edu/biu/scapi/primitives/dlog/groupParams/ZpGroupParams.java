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

import java.io.Serializable;
import java.math.BigInteger;
/**
 * This class holds the parameters of a Dlog group over Zp*.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ZpGroupParams extends GroupParams implements Serializable{

	private static final long serialVersionUID = 1458597565512141731L;

	private BigInteger p; //modulus
	private BigInteger xG; //generator value
	
	/**
	 * constructor that sets the order, generator and modulus
	 * @param q - order of the group
	 * @param xG - generator of the group
	 * @param p - modulus of the group
	 */
	public ZpGroupParams(BigInteger q, BigInteger xG, BigInteger p) {
		this.q = q;
		
		this.xG = xG;
		
		this.p = p;
	}
	
	/**
	 * Returns the prime modulus of the group
	 * @return p
	 */
	public BigInteger getP(){
		return p;
	}
	
	/**
	 * Returns the generator of the group
	 * @return xG - the generator value
	 */
	public BigInteger getXg(){
		return xG;
	}

	@Override
	public String toString() {
		return "ZpGroupParams [p=" + p + ", xG=" + xG + "]";
	}
	
}
