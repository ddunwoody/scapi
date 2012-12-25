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


package edu.biu.scapi.primitives.trapdoorPermutation.cryptopp;

import java.math.BigInteger;

import edu.biu.scapi.primitives.trapdoorPermutation.TPElement;
import edu.biu.scapi.primitives.trapdoorPermutation.TPElementSendableData;

/**
 * This class implements some common functionality of the wrappers of crypto++ trapdoor elements.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class CryptoPpTrapdoorElement implements TPElement{
	/* pointer to the CryptoPP::Integer.
	 * We save the pointer to an CryptoPP::Integer object to avoid unnecessary conversions 
	 * back and force when computing and inverting.
	 */
	protected long pointerToInteger; 
	
	//native functions. These functions are implemented in CryptoPpJavaInterface dll using the JNI tool.
	
	//returns pointer to the native object
	protected native long getPointerToElement(byte[] element);
	//returns the value of the native object
	protected native byte[] getElement(long ptr);
	//deleted the native object
	private native void deleteElement(long ptr);
	
	/**
	 * Returns pointer to the native CryptoPP Integer object.
	 * @return the pointer to the native object
	 */
	public long getPointerToElement() {
		return pointerToInteger;
	}
	
	/**
	 * Returns the value of the native Integer object as BigInteger.
	 * @return the BigInteger value of the native element
	 */
	public BigInteger getElement() {
		/*
		 * The function getElement returns the Integer value as byte array.
		 * BigInteger has a constructor that accepts this byte array and returns a BigInteger object with the same value as the Integer.
		 */
		return new BigInteger(getElement(pointerToInteger));
	}
	
	/** 
	 * @see edu.biu.scapi.primitives.trapdoorPermutation.TPElement#generateSendableData()
	 */
	@Override
	public TPElementSendableData generateSendableData() {
		return new TPElementSendableData(getElement());
	}
	
	/**
	 * deletes the related trapdoor permutation object
	 */
	protected void finalize() throws Throwable {
		
		//deletes from the dll the dynamic allocation of the Integer.
		deleteElement(pointerToInteger);
		
		super.finalize();
	}
	
	//loads the dll
	 static {
	        System.loadLibrary("CryptoPPJavaInterface");
	 }
}
