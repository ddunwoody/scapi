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
package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScCramerShoupPublicKey.ScCramerShoupPublicKeySendableData;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

public class ScElGamalPublicKey implements ElGamalPublicKey {

	private static final long serialVersionUID = 8645777933993577969L;
	private GroupElement h;
	
	public ScElGamalPublicKey(GroupElement h){
		this.h = h;
	}
	
	@Override
	public String getAlgorithm() {
		
		return "ElGamal";
	}

	@Override
	public byte[] getEncoded() {
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}
	
	public GroupElement getH(){
		return h;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.keys.CramerShoupPublicKey#generateSendableData()
	 */
	@Override
	public KeySendableData generateSendableData() {
		return new ScElGamalPublicKeySendableData(h.generateSendableData());
	}
	
	
	static public class ScElGamalPublicKeySendableData implements KeySendableData {
			private static final long serialVersionUID = 334589064982559017L;
		private GroupElementSendableData c;

		public ScElGamalPublicKeySendableData(GroupElementSendableData c) {
			super();
			this.c = c;
		}

		public GroupElementSendableData getC() {
			return c;
		}
		
		
	}

}
