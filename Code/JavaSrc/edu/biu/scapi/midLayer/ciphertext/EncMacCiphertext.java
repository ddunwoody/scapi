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
/**
 * 
 */
package edu.biu.scapi.midLayer.ciphertext;

import java.io.Serializable;

/**
 * This class is a container for cipher-texts that include actual encrypted data and the resulting tag.
 * This is a concrete decorator in the Decorator Pattern used for Symmetric Ciphertext.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class EncMacCiphertext extends SymCiphertextDecorator implements Serializable {

	private static final long serialVersionUID = 5005071569923354531L;

	//The MAC tag.
	byte[] tag;

	/**
	 * Constructs a container for Encryption and Authentication Ciphertext. 
	 * @param cipher symmetric ciphertext to which we need to add a MAC-tag.
	 * @param tag the MAC-tag we need to add to the ciphertext.
	 */
	public EncMacCiphertext(SymmetricCiphertext cipher, byte[] tag){
		super(cipher);
		this.tag = tag;
	}
	
	/**
	 * 
	 * @return the MAC-tag of this authenticated ciphertext.
	 */
	public byte[] getTag() {
		return tag;
	}
	
}
