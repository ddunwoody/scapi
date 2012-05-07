package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;

import edu.biu.scapi.exceptions.UnInitializedException;

/**
 * Marker interface. Every class that implements it is signed as Zp*
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface DlogZp extends DlogGroup{
	
	/**
	 * Creates an element with the given x value 
	 * @param x
	 * @return the created element
	 * @throws UnInitializedException 
	 */
	public ZpElement getElement (BigInteger x, Boolean bCheckMembership);
}
