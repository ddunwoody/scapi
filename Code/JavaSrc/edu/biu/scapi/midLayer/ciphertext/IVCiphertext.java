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
 * This class is a container for cipher-texts that include actual cipher data and the IV used.
 * This is a concrete decorator in the Decorator Pattern used for Symmetric Ciphertext.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class IVCiphertext extends SymCiphertextDecorator implements Serializable {
	
	private static final long serialVersionUID = -503467002396867700L;

	private byte[] iv;
	
	/**
	 * Constructs a container for Ciphertexts that need an IV. 
	 * @param cipher symmetric ciphertext to which we need to add an IV.
	 * @param iv the IV we need to add to the ciphertext.
	 */
	public IVCiphertext(SymmetricCiphertext cipher, byte[] iv){
		super(cipher);
		this.iv = iv;
	}
	
	/**
	 * 
	 * @return the IV of this ciphertext-with-IV.
	 */
	public byte[] getIv(){
		return iv;
	}	
	
}
