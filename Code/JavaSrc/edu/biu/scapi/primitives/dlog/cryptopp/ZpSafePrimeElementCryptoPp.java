package edu.biu.scapi.primitives.dlog.cryptopp;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.dlog.ZpSafePrimeElement;

/**
 * This class is an adapter class of Crypto++ to a ZpElement in SCAPI.<p>
 * It holds a pointer to a Zp element in Crypto++. It implements all the functionality of a Zp element.  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ZpSafePrimeElementCryptoPp implements ZpSafePrimeElement{

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
	public ZpSafePrimeElementCryptoPp(BigInteger x, BigInteger p, Boolean bCheckMembership) throws IllegalArgumentException{
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
	 * input: modulus p of length len.
     *  BigInteger x;
     *  For i = 1 to 2*len:
	 *  x <- {0, 1}^len
	 *  if x<p return x^2
     *  Return “fail"
     *  
	 * @param zp - dlogGroup
	 * @throws IllegalArgumentException
	 */
	public ZpSafePrimeElementCryptoPp(BigInteger p)throws IllegalArgumentException{
		
		int len = p.bitLength(); //get the security parameter for the algorithm
		SecureRandom generator = new SecureRandom();
		BigInteger element = null;
		//find a number in the range [1, ..., p-1]
		for(int i=0; i<(2*len); i++){
			element = new BigInteger(len, generator); //get a number between 0 to 2^p
			element = element.add(new BigInteger("1"));  //number in the range [1, ..., 2^p-1]
			//if the number is in the range, calculate its power to get a number in the subgroup and set the power as the element. 
			if (element.compareTo(p)<0){
				element = element.pow(2).mod(p);
				pointerToElement = getPointerToElement(element.toByteArray());
				break;
			}
		}
		//if the algorithm failed, write it to the log
		if (element.compareTo(p.subtract(BigInteger.ONE))>0)
			Logging.getLogger().log(Level.WARNING, "couldn't find a random element");
	}
	
	/*
	 * Constructor that gets pointer to element and set it.
	 * Only our inner functions uses this constructor to set an element. 
	 * The long value is a pointer which excepted by our native functions.
	 * @param ptr
	 */
	ZpSafePrimeElementCryptoPp(long ptr){
		pointerToElement = ptr;
	}
	
	/*
	 * return the pointer to the element
	 * @return
	 */
	long getPointerToElement(){
		return pointerToElement;
	}
	
	/**
	 * @return BigInteger - value of the element
	 */
	public BigInteger getElementValue(){
		return new BigInteger(getElement(pointerToElement));
	}
	
	/**
	 * Checks if the given GroupElement is equal to this groupElement.
	 * @param elementToCompare
	 * @return true if the given element is equal to this element. false, otherwise.
	 */
	public boolean equals(Object elementToCompare){
		if (!(elementToCompare instanceof ZpSafePrimeElementCryptoPp)){
			return false;
		}
		ZpSafePrimeElementCryptoPp element = (ZpSafePrimeElementCryptoPp) elementToCompare;
		if (element.getElementValue().compareTo(getElementValue()) == 0){
			return true;
		}
		return false;
	}
	
	public void release(){
		//delete from the dll the dynamic allocation of the Integer.
		deleteElement(pointerToElement);
		
	}
	/*
	 * delete the related Dlog element object
	 */
	protected void finalize() throws Throwable {
		
		//delete from the dll the dynamic allocation of the Integer.
		deleteElement(pointerToElement);
		
		super.finalize();
	}
	
	 static {
	        System.loadLibrary("CryptoPPJavaInterface");
	 }
}
