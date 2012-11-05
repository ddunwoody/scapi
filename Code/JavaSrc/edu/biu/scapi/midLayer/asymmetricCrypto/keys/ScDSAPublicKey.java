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

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScCramerShoupPublicKey.ScCramerShoupPublicKeySendableData;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

public class ScDSAPublicKey implements DSAPublicKey{

	/**
	 * 
	 */
	private static final long serialVersionUID = 7578867149669452105L;
	private GroupElement y;

	public ScDSAPublicKey(GroupElement y){
		this.y = y;
	}

	@Override
	public GroupElement getY() {
		return y;
	}

	@Override
	public String getAlgorithm() {
		return "DSA";
	}

	@Override
	public byte[] getEncoded() {
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.keys.CramerShoupPublicKey#generateSendableData()
	 */
	@Override
	public KeySendableData generateSendableData() {
		return new ScDSAPublicKeySendableData(y.generateSendableData());
	}


	static public class ScDSAPublicKeySendableData implements KeySendableData {

		private static final long serialVersionUID = -3966023977520093223L;
		private GroupElementSendableData y;
		public ScDSAPublicKeySendableData(GroupElementSendableData y) {
			super();
			this.y = y;
		}
		public GroupElementSendableData getY() {
			return y;
		}

		//Even though ScCramerShoupPublicKey should be Serializable (it implements the Key interface which is Serializable), we need to stop the regular serialization mechanism.
		//Cramer Shoup's public key contains GroupElements and cannot be serialized in the regular way, therefore, we stop the serialization here. 
		//In order to serialize this object you need to call the generateSendableData() function which returns a KeySendableData object. This object can be serialized.
		//In order to deserialize the public key in the other side the CramerShoup::generatePublicKey(KeySendableData) function needs to be called.
		private void writeObject(ObjectOutputStream out) throws IOException
		{
			throw new NotSerializableException("To serialize this object call the generateSendableData() function which returns a KeySendableData object which can be serialized");
		}
		private void readObject(ObjectInputStream in) throws IOException
		{
			throw new NotSerializableException("To serialize this object call the generateSendableData() function which returns a KeySendableData object which can be serialized");
		}
	}
}
