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
 * This class is a container that encapsulates the cipher data resulting from applying the CramerShoupDDH encryption.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CramerShoupOnGroupElementCiphertext extends CramerShoupCiphertext {
	
	private GroupElement e;
	
	public CramerShoupOnGroupElementCiphertext(GroupElement u1, GroupElement u2, GroupElement e, GroupElement v) {
		super(u1, u2, v);
		this.e = e;
	}

	public GroupElement getE() {
		return e;
	}
	public AsymmetricCiphertextSendableData generateSendableData(){
		return new CrShOnGroupElSendableData(getU1().generateSendableData(), getU2().generateSendableData(), getV().generateSendableData(), e.generateSendableData());
	}
	
	static public class CrShOnGroupElSendableData extends CramerShoupCiphertextSendableData {

		
		private static final long serialVersionUID = 4696047521259797209L;

		private GroupElementSendableData e;
		/**
		 * @param u1
		 * @param u2
		 * @param u3
		 */
		public CrShOnGroupElSendableData(GroupElementSendableData u1,
				GroupElementSendableData u2, GroupElementSendableData u3, GroupElementSendableData e) {
			super(u1, u2, u3);
			this.e =  e;
		}
		public GroupElementSendableData getE() {
			return e;
		}

	}


}
