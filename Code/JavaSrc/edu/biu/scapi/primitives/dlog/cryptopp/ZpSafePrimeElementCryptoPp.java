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


package edu.biu.scapi.primitives.dlog.cryptopp;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.primitives.dlog.GroupElementSendableData;
import edu.biu.scapi.primitives.dlog.ZpElementSendableData;
import edu.biu.scapi.primitives.dlog.ZpSafePrimeElement;

/**
 * This class is an adapter class of Crypto++ to a ZpElement in SCAPI.<p>
 * It holds a pointer to a Zp element in Crypto++. It implements all the functionality of a Zp element.  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ZpSafePrimeElementCryptoPp implements ZpSafePrimeElement {

	private long pointerToElement;

	private native long getPointerToElement(byte[] element);
	private native long deleteElement(long element);
	private native byte[] getElement(long element);

	/**
	 * This constructor accepts x value and DlogGroup.
	 * If x is valid, sets it; else, throws exception 
	 * @param x
	 * @param zp
	 * @throws IllegalArgumentException
	 */
	ZpSafePrimeElementCryptoPp(BigInteger x, BigInteger p, Boolean bCheckMembership) throws IllegalArgumentException{
		if(bCheckMembership){
			BigInteger q = p.subtract(BigInteger.ONE).divide(new BigInteger("2"));
			//if the element is in the expected range, set it. else, throw exception
			if ((x.compareTo(BigInteger.ZERO)>0) && (x.compareTo(p.subtract(BigInteger.ONE))<=0)){
				if ((x.modPow(q, p)).compareTo(BigInteger.ONE)==0){
					pointerToElement = getPointerToElement(x.toByteArray());
				} else throw new IllegalArgumentException("Cannot create Zp element. Requested value " + x + " is not in the range of this group.");
			} 
			else throw new IllegalArgumentException("Cannot create Zp element. Requested value " + x + " is not in the range of this group.");
		} else {
			pointerToElement = getPointerToElement(x.toByteArray());
		}
	}

	/**
	 * Constructor that gets DlogGroup and chooses random element with order q.
	 * The algorithm is: 
	 * input: modulus p 
	 * choose a random element between 1 to p-1
	 * calculate element^2 mod p
     *  
	 * @param p - group modulus
	 * @throws IllegalArgumentException
	 */
	ZpSafePrimeElementCryptoPp(BigInteger p){
		this(p, new SecureRandom());
					
	}
	
	/**
	 * Constructor that gets DlogGroup and chooses random element with order q.
	 * The algorithm is: 
	 * input: modulus p 
	 * choose a random element between 1 to p-1
	 * calculate element^2 mod p
     *  
	 * @param p - group modulus
	 * @throws IllegalArgumentException
	 */
	ZpSafePrimeElementCryptoPp(BigInteger p, SecureRandom random){
		BigInteger element = null;
		// find a number in the range [1, ..., p-1]
		element = BigIntegers.createRandomInRange(BigInteger.ONE, p.subtract(BigInteger.ONE), random);
			
		//calculate its power to get a number in the subgroup and set the power as the element. 
		element = element.pow(2).mod(p);
		pointerToElement = getPointerToElement(element.toByteArray());
					
	}

	/*
	 * Constructor that gets pointer to element and set it.
	 * Only our inner functions uses this constructor to set an element. 
	 * The long value is a pointer which excepted by our native functions.
	 * @param ptr
	 */
	ZpSafePrimeElementCryptoPp(long ptr) {
		pointerToElement = ptr;
	}

	/*
	 * return the pointer to the element
	 * @return
	 */
	long getPointerToElement() {
		return pointerToElement;
	}

	/**
	 * @return BigInteger - value of the element
	 */
	public BigInteger getElementValue() {
		return new BigInteger(getElement(pointerToElement));
	}
	
	/**
	 * This function checks if this element is the identity of the Dlog group.
	 * @return <code>true</code> if this element is the identity of the group; <code>false</code> otherwise.
	 */
	public boolean isIdentity(){
		
		if (getElementValue().equals(BigInteger.ONE)) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Checks if the given GroupElement is equal to this groupElement.
	 * 
	 * @param elementToCompare
	 * @return true if the given element is equal to this element. false, otherwise.
	 */
	public boolean equals(Object elementToCompare) {
		if (!(elementToCompare instanceof ZpSafePrimeElementCryptoPp)) {
			return false;
		}
		ZpSafePrimeElementCryptoPp element = (ZpSafePrimeElementCryptoPp) elementToCompare;
		if (element.getElementValue().compareTo(getElementValue()) == 0) {
			return true;
		}
		return false;
	}


	@Override
	public String toString() {
		return "ZpSafePrimeElementCryptoPp [element value="	+  getElementValue() + "]";
	}
	
	/*
	 * delete the related Dlog element object
	 */
	protected void finalize() throws Throwable {

		// delete from the dll the dynamic allocation of the Integer.
		deleteElement(pointerToElement);

		super.finalize();
	}

	static {
		System.loadLibrary("CryptoPPJavaInterface");
	}

	/** 
	 * @see edu.biu.scapi.primitives.dlog.GroupElement#generateSendableData()
	 */
	@Override
	public GroupElementSendableData generateSendableData() {
		return new ZpElementSendableData(getElementValue());
	}
}
