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

import java.math.BigInteger;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class BigIntegerCiphertext implements AsymmetricCiphertext, AsymmetricCiphertextSendableData {
	
	private static final long serialVersionUID = 5129403259299156094L;
	
	private BigInteger cipher;

	public BigIntegerCiphertext(BigInteger cipher) {
		super();
		this.cipher = cipher;
	}

	public BigInteger getCipher() {
		return cipher;
	}

	/**
	 * @see edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext#generateSendableData()
	 */
	@Override
	public AsymmetricCiphertextSendableData generateSendableData() {
		//Since BigIntegerCiphertext is both an AsymmetricCiphertext and a AsymmetricCiphertextSendableData, on the one hand it has to implement
		//the generateSendableData() function, but on the other hand it is in itself an AsymmetricCiphertextSendableData, so we do not really
		//generate sendable data, but just return this object.
		return this;
	}
	
}
