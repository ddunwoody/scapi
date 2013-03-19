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


package edu.biu.scapi.midLayer.plaintext;

import java.io.Serializable;
import java.util.Arrays;

/**
 * This class holds the plaintext as a ByteArray.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ByteArrayPlaintext implements Plaintext, PlaintextSendableData  {
	/**
	 * 
	 */
	private static final long serialVersionUID = 7793696997942346814L;
	private byte[] text = null;
	
	public ByteArrayPlaintext (byte[] text) {
		this.text = text;
	}
	
	public byte[] getText() {
		return text;
	}
	
	@Override
	public boolean equals(Object plaintext){
		if (!(plaintext instanceof ByteArrayPlaintext)){
			return false;
		}
		byte[] text2 = ((ByteArrayPlaintext) plaintext).getText();
		
		if (text.length != text2.length){
			return false;
		}
		
		for (int i=0; i<text.length; i++){
			if (text[i] != text2[i]){
				return false;
			}
		}
		
		return true;
	}
	

	/**
	 * This function is used when a Plaintext needs to be sent via a edu.biu.scapi.comm.Channel or any other means of sending data (including serialization). 
	 * It retrieves all the data needed to reconstruct this Plaintext at a later time and/or in a different VM. It puts all the data in an instance of the 
	 * relevant class that implements the PlaintextSendableData interface.
	 * In order to deserialize this into a ByteArrayPlaintext all you need to do is cast the serialized object with (ByteArrayPlaintext)
	 */
	@Override
	public PlaintextSendableData generateSendableData() {
		//Since ByteArrayPlainText is both a Plaintext and a PlaintextSendableData, on the one hand it has to implement
		//the generateSendableData() function, but on the other hand it is in itself an PlaintextSendableData, so we do not really
		//generate sendable data, but just return this object.
		return this;
	}

	@Override
	public String toString() {
		return "ByteArrayPlaintext [text=" + Arrays.toString(text) + "]";
	}
	
	
}
