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
