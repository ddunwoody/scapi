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
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

/**
 * This class is a container that encapsulates the cipher data resulting from applying the El Gamal encryption.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ElGamalOnGroupElementCiphertext implements AsymmetricCiphertext {
	//First part of the ciphertext.
	private GroupElement cipher1;
	//Second part of the ciphertext.
	private GroupElement cipher2;
	
	/**
	 * Create an instance of this container class 
	 * @param c1 the first part of the cihertext
	 * @param c2 the second part of the ciphertext
	 */
	public ElGamalOnGroupElementCiphertext(GroupElement c1, GroupElement c2){
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
	public GroupElement getC2(){
		return cipher2;
	}

	/**
	 * @see edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext#generateSendableData()
	 */
	@Override
	public AsymmetricCiphertextSendableData generateSendableData() {
		return new ElGamalOnGrElSendableData(cipher1.generateSendableData(), cipher2.generateSendableData());
	}
	
	static public class ElGamalOnGrElSendableData implements AsymmetricCiphertextSendableData {


		private static final long serialVersionUID = 4480691511084748707L;

		GroupElementSendableData cipher1;
		GroupElementSendableData cipher2;
		public ElGamalOnGrElSendableData(GroupElementSendableData cipher1,
				GroupElementSendableData cipher2) {
			super();
			this.cipher1 = cipher1;
			this.cipher2 = cipher2;
		}
		public GroupElementSendableData getCipher1() {
			return cipher1;
		}
		public GroupElementSendableData getCipher2() {
			return cipher2;
		}
		
		
		
	}

}
