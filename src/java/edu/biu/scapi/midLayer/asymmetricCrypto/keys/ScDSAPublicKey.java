/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

/**
* This class represents a Public Key suitable for the Digital Signature Algorithm. Although the constructor is public, it should only be instantiated by the 
* Digital Signature itself via the generateKey function. 
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
public class ScDSAPublicKey implements DSAPublicKey{

	
	private static final long serialVersionUID = 7578867149669452105L;
	private GroupElement y;

	public ScDSAPublicKey(GroupElement y){
		this.y = y;
	}
	
	public ScDSAPublicKey(ScDSAPublicKeySendableData data, DlogGroup dlog){
		this(dlog.generateElement(false, data.getY()));
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

	/**
	 * (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.keys.DSAPublicKey#generateSendableData()
	 */
	@Override
	public KeySendableData generateSendableData() {
		return new ScDSAPublicKeySendableData(y.generateSendableData());
	}

	//Nested class that holds the sendable data of the outer class
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

		//Even though ScDSAPublicKey should be Serializable (it implements the Key interface which is Serializable), we need to stop the regular serialization mechanism.
		//DSA's public key contains GroupElements and cannot be serialized in the regular way, therefore, we stop the serialization here. 
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
