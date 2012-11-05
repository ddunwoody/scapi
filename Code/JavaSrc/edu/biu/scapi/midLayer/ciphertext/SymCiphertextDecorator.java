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
 * The decorator pattern has been used to implement different types of symmetric ciphertext.<p>   
 * This abstract class is the decorator part of the pattern. It allows wrapping the base symmetric ciphertext with extra functionality.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
abstract class SymCiphertextDecorator implements SymmetricCiphertext, Serializable{

	private static final long serialVersionUID = -5676459536949678320L;

	//The symmetric ciphertext we want to decorate.
	protected SymmetricCiphertext cipher;
	
	public SymCiphertextDecorator() {
		super();
	}

	/**
	 * This constructor gets the symmetric ciphertext that we need to decorate.
	 * @param cipher
	 */
	public SymCiphertextDecorator(SymmetricCiphertext cipher){
		this.cipher = cipher;
	}
	
	/**
	 * 
	 * @return the undecorated cipher.
	 */
	public SymmetricCiphertext getCipher() {
		return this.cipher;
	}
	
	/*
	 * (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext#getBytes()
	 * Delegate to underlying (decorated) ciphertext. This behavior can be overridden by inheriting classes.
	 */
	public byte[] getBytes(){
		return cipher.getBytes();
	}

	/*
	 * (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext#getLength()
	 * Delegate to underlying (decorated) ciphertext. This behavior can be overridden by inheriting classes.
	 */
	@Override
	public int getLength() {
		return cipher.getLength();
	}
}
