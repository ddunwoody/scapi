package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;

/**
 * This is a marker interface. Every class that implements it is signed as Zp* element. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface ZpElement extends GroupElement{
	/**
	 * This function returns the actual "integer" value of this element; which is an element of a given Dlog over Zp*.
	 * @return integer value of this Zp element.
	 */
	public BigInteger getElementValue();
}
