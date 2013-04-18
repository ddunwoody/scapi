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


package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import edu.biu.scapi.exceptions.ScapiRuntimeException;

/** 
 * This class implements some common functionality of trapdoor permutation.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public abstract class TrapdoorPermutationAbs implements TrapdoorPermutation {
	
	protected PrivateKey privKey = null;        //private key
	protected PublicKey pubKey = null;          //public key
	protected BigInteger modulus = null;		//the modulus of the permutation. It must be such that modulus = p*q and p = q = 3 mod 4
	protected boolean isKeySet = false;		    // indicates if this object is initialized or not. Set to false until init is called

	
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
		//sets the class members with the keys
		pubKey = publicKey;
		privKey = privateKey;
		isKeySet = true; // mark this object as initialized
	}

	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		//sets the class member with the public key
		pubKey = publicKey;
		isKeySet = true; // mark this object as initialized
	}
	

	public boolean isKeySet() {
		return isKeySet;
	}

	public PublicKey getPubKey(){
		if (!isKeySet()){
			throw new IllegalStateException("public key isn't set");
		}
		return pubKey;
	}
	
	public BigInteger getModulus(){
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		return modulus;
	}
	
	
	/** 
	 * Compute the hard core predicate of the given tpElement, by return the least significant bit of the element. 
	 *
	 * @param tpEl the element to compute the hard core predicate on
	 * @return byte the hard core predicate. In java, the smallest types are boolean and byte. 
	 * We chose to return a byte since many times we need to concatenate the result of various predicates 
	 * and it will be easier with a byte than with a boolean.
	 */
	public byte hardCorePredicate(TPElement tpEl) {
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		/*
		 *  We use this implementation both in RSA permutation and in Rabin permutation. 
		 * Thus, We implement it in TrapdoorPermutationAbs and let derived classes override it if needed. 
		 */
		//gets the element value as byte array
		BigInteger elementValue = tpEl.getElement();
		byte[] bytesValue = elementValue.toByteArray();
		
		//returns the least significant bit (byte, as we said above)
		return bytesValue[bytesValue.length - 1];
	}

	/** 
	 * Computes the hard core function of the given tpElement, by return the log (N) least significant bits of 
	 * the element. 
	 * @param tpEl the element to compute the hard core function on
	 * @return byte[] - log (N) least significant bits
	 */
	public byte[] hardCoreFunction(TPElement tpEl) {
		
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		/*
		 * We use this implementation both in RSA permutation and in Rabin permutation. 
		 * Thus, We implement it in TrapdoorPermutationAbs and let derived classes override it if needed. 
		 */
		//gets the element value as byte array
		BigInteger elementValue = tpEl.getElement();
		byte[] elementBytesValue = elementValue.toByteArray();
		
		//the number of bytes to get the log (N) least significant bits
		double logBits = (modulus.bitCount()/2);  //log N bits
		int logBytes = (int) Math.ceil(logBits/8); //log N bites in bytes
		
		//if the element length is less than log(N), the return byte[] should be all the element bytes
		int size = Math.min(logBytes, elementBytesValue.length);
		byte[] leastSignificantBytes = new byte[size];
		//copies the bytes to the output array
		System.arraycopy(elementBytesValue, elementBytesValue.length-size, leastSignificantBytes, 0, size);
		return leastSignificantBytes;
	
	}
	

	/** 
	 * @see edu.biu.scapi.primitives.trapdoorPermutation.TrapdoorPermutation#generateTPElement(edu.biu.scapi.primitives.trapdoorPermutation.TPElementSendableData)
	 * @deprecated As of SCAPI-V1-0-2-2 use reconstructTPElement(TPElementSendableData data)
	 */
	@Deprecated public TPElement generateTPElement(TPElementSendableData data){
		return generateTPElement(data.getX());
	}

	/**
	 * {@inheritDoc}
	 */
	public TPElement reconstructTPElement(TPElementSendableData data){
		return generateTPElement(data.getX());
	}
}
