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

import java.io.Serializable;

/**
 * This class represents the most basic symmetric ciphertext.
 * It is a data holder for the ciphertext calculated by some symmetric encryption algorithm. <p>
 * It only holds the actual "ciphered" bytes and not any additional information like for example in El Gamal encryption.
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 */
public class ByteArraySymCiphertext implements SymmetricCiphertext, Serializable {

	private static final long serialVersionUID = -5263587288535853337L;

	byte[] data;
	
	
	/**
	 * The encrypted bytes need to be passed to construct this holder.
	 * @param data
	 */
	public ByteArraySymCiphertext(byte[] data) {
		this.data = data;
	}

	@Override
	public byte[] getBytes() {
		return data;
	}

	@Override
	public int getLength() {
		return data.length;
	}

	

}
