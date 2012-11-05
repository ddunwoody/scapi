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

public class CramerShoupOnByteArrayCiphertext extends CramerShoupCiphertext{

	private byte[] e;
	
	public CramerShoupOnByteArrayCiphertext(GroupElement u1, GroupElement u2, byte[] e, GroupElement v) {
		super(u1, u2, v);
		this.e = e;
		
	}

	public byte[] getE() {
		return e;
	}

	public AsymmetricCiphertextSendableData generateSendableData(){
		return new CrShOnByteArraySendableData(getU1().generateSendableData(), getU2().generateSendableData(), getV().generateSendableData(), e);
	}
	
	static public class CrShOnByteArraySendableData extends CramerShoupCiphertextSendableData {

		private static final long serialVersionUID = 8318304796976977262L;

		private byte[] e;
		/**
		 * @param u1
		 * @param u2
		 */
		public CrShOnByteArraySendableData(GroupElementSendableData u1, GroupElementSendableData u2, GroupElementSendableData v, byte[] e) {
			super(u1, u2, v);
			this.e = e;
		}
		public byte[] getE() {
			return e;
		}

	}

}
