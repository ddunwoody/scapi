package edu.biu.scapi.primitives.trapdoorPermutation.cryptopp;

import java.math.BigInteger;


/**
 * Concrete class of TPElement for Rabin element. This class is a wrapper of Crypto++ Integer object.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public final class CryptoPpRabinElement extends CryptoPpTrapdoorElement{
	//native function. This function is implemented in CryptoPpJavaInterface dll using the JNI tool.
	//returns a pointer to a random native integer object
	private native long getPointerToRandomRabinElement(byte[] modN); 
	
	/**
	 * Constructor that chooses a random element according to the given modulus.
	 * @param modN the modulus
	 */
	public CryptoPpRabinElement(BigInteger modN) {
		/*
		 * samples a number between 1 to mod n with a square root mod(N)
		 */
		pointerToInteger = getPointerToRandomRabinElement(modN.toByteArray());
	}
		
	/**
	 * Constructor that gets the mod n and a value to be the element. 
	 * Because the element doesn't contains p and q, we can't check if the value has a square root modN. 
	 * So we can't know if the element is valid Rabin element. Therefore, we don't do any checks and save 
	 * the value as is. Any trapdoor permutation that use this element will check validity before using.
	 * @param modN - modulus
	 * @param x - the element value
	 */
	public CryptoPpRabinElement(BigInteger modN, BigInteger x) {
		pointerToInteger = getPointerToElement(x.toByteArray());
	}
	
	/**
	 * Constructor that gets a pointer to a native element and sets it as the native element pointer.
	 * We assume that the given long argument is indeed a pointer to a native element.
	 * @param ptr pointer to a native element
	 */
	CryptoPpRabinElement(long ptr) {
		
		pointerToInteger = ptr;
	}
}
