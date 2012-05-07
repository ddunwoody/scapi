package edu.biu.scapi.primitives.trapdoorPermutation.cryptopp;

import java.math.BigInteger;


/** 
 * Concrete class of TPElement for RSA element. This class is a wrapper of Crypto++ Integer object.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public final class CryptoPpRSAElement extends CryptoPpTrapdoorElement{
	//native function. This function is implemented in CryptoPpJavaInterface dll using the JNI tool.
	//returns a pointer to a random native integer object
	private native long getPointerToRandomRSAElement(byte[] modN);
	
	/**
	 * Constructor that chooses a random element according to the given modulus.
	 * @param modN the modulus
	 */
	public CryptoPpRSAElement(BigInteger modN) {
		/*
		 * calls a native function that samples a random number between 1 to mondN-1 and returns its pointer.
		 * sets the pointer to be the element pointer
		 */
		pointerToInteger = getPointerToRandomRSAElement (modN.toByteArray());
	}
		
	/**
	 * Constructor that gets a modulus and a value. If the value is a valid RSA element according to the modulus, sets it as the element.
	 * @param modN - the modulus
	 * @param x - the element value
	 * @throws IllegalArgumentException if the element is not legal according the modulus
	 */
	public CryptoPpRSAElement(BigInteger modN, BigInteger x) throws IllegalArgumentException{
		
		/*checks if the value is valid (between 1 to (modN) - 1 ).
		  if valid - calls a native function that returns pointer and sets it to be the element pointer
		  if not valid - throws exception */
		if(((x.compareTo(BigInteger.ZERO))>0) && (x.compareTo(modN)<0)) {
				pointerToInteger = getPointerToElement(x.toByteArray());
		} else {
			throw new IllegalArgumentException("element out of range");
		}
	}
	
	/**
	 * Constructor that gets a pointer to a native element and sets it as the native element pointer.
	 * We assume that the given long argument is indeed a pointer to a native element.
	 * @param ptr pointer to a native element
	 */
	CryptoPpRSAElement(long ptr) {
		
		pointerToInteger = ptr;
	}
}
