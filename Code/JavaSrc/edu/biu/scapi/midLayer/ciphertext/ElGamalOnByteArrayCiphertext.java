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
package edu.biu.scapi.midLayer.ciphertext;

import edu.biu.scapi.primitives.dlog.GroupElement;

public class ElGamalOnByteArrayCiphertext implements AsymmetricCiphertext{

	//First part of the ciphertext.
	private GroupElement cipher1;
	//Second part of the ciphertext.
	private byte[] cipher2;
	
	/**
	 * Create an instance of this container class 
	 * @param c1 the first part of the cihertext
	 * @param c2 the second part of the ciphertext
	 */
	public ElGamalOnByteArrayCiphertext(GroupElement c1, byte[] c2){
		this.cipher1 = c1;
		this.cipher2 = c2;
	}
	
	/**
	 * 
	 * @return the first part of the ciphertext
	 */
	public GroupElement getC1(){
		return cipher1;
	}
	
	/**
	 * 
	 * @return the second part of the ciphertext
	 */
	public byte[] getC2(){
		return cipher2;
	}
}
