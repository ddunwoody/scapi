package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;

import edu.biu.scapi.exceptions.UnInitializedException;

/**
 * Marker interface. Every class that implements it is signed as elliptic curve.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface DlogEllipticCurve extends DlogGroup{
	
	/**
	 * Creates a point with the given x,y values 
	 * @param x
	 * @param y
	 * @return the created ECPoint (x,y)
	 * @throws UnInitializedException 
	 */
	public ECElement getElement(BigInteger x, BigInteger y);
	
	/**
	 * 
	 * @return the infinity point of this dlog group
	 */
	public ECElement getInfinity();
	public String getCurveName();
	
	public String getFileName();
}
