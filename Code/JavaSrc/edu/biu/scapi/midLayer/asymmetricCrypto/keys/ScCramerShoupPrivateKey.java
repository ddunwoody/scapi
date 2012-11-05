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
package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScCramerShoupPrivateKey implements CramerShoupPrivateKey, KeySendableData {


	private BigInteger x1;
	private BigInteger x2;
	private BigInteger y1;
	private BigInteger y2;
	private BigInteger z;

	/**
	 * 
	 */
	public ScCramerShoupPrivateKey(BigInteger x1, BigInteger x2, BigInteger y1,
			BigInteger y2, BigInteger z) {
		super();
		this.x1 = x1;
		this.x2 = x2;
		this.y1 = y1;
		this.y2 = y2;
		this.z = z;
	}



	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {

		return "CramerShoup";
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		return null;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		return null;
	}

	@Override
	public BigInteger getPrivateExp1() {
		return x1;
	}

	@Override
	public BigInteger getPrivateExp2() {
		return x2;
	}

	@Override
	public BigInteger getPrivateExp3() {
		return y1;
	}

	@Override
	public BigInteger getPrivateExp4() {
		return y2;
	}

	@Override
	public BigInteger getPrivateExp5() {
		return z;
	}



	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.keys.CramerShoupPrivateKey#generateSendableData()
	 */
	@Override
	public KeySendableData generateSendableData() {
		//Since ScCramerShoupPrivateKey is both a PrivateKey and a KeySendableData, on the one hand it has to implement
		//the generateSendableData() function, but on the other hand it is in itself an KeySendableData, so we do not really
		//generate sendable data, but just return this object.
		return this;
	}

	/*
	//Even though ScCramerShoupPrivateKey should be Serializable (it implements the Key interface which is Serializable), we need to stop the regular serialization mechanism.
	//In the cas of Cramer Shoup's private key, we could serialize it in the regular way because its fields are only BigInteger, but for the sake of 
	//consistency with Cramer Shoup's public key that contains GroupElements and cannot be serialized in the regular way we stop the serialization here too!
	private void writeObject(ObjectOutputStream out) throws IOException
	{
		throw new NotSerializableException("To serialize this object call the generateSendableData() function which returns a KeySendableData object which can be serialized");
	}
	private void readObject(ObjectInputStream in) throws IOException
	{
		throw new NotSerializableException("To serialize this object call the generateSendableData() function which returns a KeySendableData object which can be serialized");
	}
	*/

}
