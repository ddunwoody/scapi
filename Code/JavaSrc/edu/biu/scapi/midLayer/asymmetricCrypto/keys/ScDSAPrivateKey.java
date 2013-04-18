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

import java.math.BigInteger;

/**
* This class represents a Private Key suitable for the Digital Signature Algorithm. Although the constructor is public, it should only be instantiated by the 
* Digital Signature itself via the generateKey function. 
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
public class ScDSAPrivateKey implements DSAPrivateKey, KeySendableData{

	private static final long serialVersionUID = -8583117475560439512L;
	private BigInteger x;
	
	public ScDSAPrivateKey(BigInteger x){
		this.x = x;
	}
	
	@Override
	public BigInteger getX() {
		
		return x;
	}
	
	@Override
	public String getAlgorithm() {
		
		return null;
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
	 * This function is used when an DSA Private Key needs to be sent via a {@link edu.biu.scapi.comm.Channel} or any other means of sending data (including serialization).
	 * It retrieves all the data needed to reconstruct this Private Key at a later time and/or in a different VM.
	 * It puts all the data in an instance of the relevant class that implements the KeySendableData interface.
	 * In order to deserialize this into a DSAPrivateKey all you need to do is cast the serialized object with (DSAPrivateKey)
	 * @return the KeySendableData object
	 */
	@Override
	public KeySendableData generateSendableData() {
		//Since ScDSAPrivateKey is both a PrivateKey and a KeySendableData, on the one hand it has to implement
		//the generateSendableData() function, but on the other hand it is in itself an KeySendableData, so we do not really
		//generate sendable data, but just return this object.
		return this;
	}

}
