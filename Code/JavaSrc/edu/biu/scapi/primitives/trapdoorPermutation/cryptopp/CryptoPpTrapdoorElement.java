package edu.biu.scapi.primitives.trapdoorPermutation.cryptopp;

import java.math.BigInteger;

import edu.biu.scapi.primitives.trapdoorPermutation.TPElement;

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
