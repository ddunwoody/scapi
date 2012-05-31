package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;


/**
 * Marker interface. Every class that implements it is signed as elliptic curve.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface DlogEllipticCurve extends DlogGroup {

	/**
	 * Creates a point with the given x,y values 
	 * @param x
	 * @param y
	 * @return the created ECPoint (x,y)
	 */
	public ECElement generateElement(BigInteger x, BigInteger y) throws IllegalArgumentException;
	
	/**
	 * 
	 * @return the infinity point of this dlog group
	 */
	public ECElement getInfinity();

	/**
	 * 
	 * @return the name of the curve. For example - P-192.
	 */
	public String getCurveName();

	/**
	 * 
	 * @return the properties file where the curves are defined.
	 */
	public String getFileName();
}
