package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;


/**
 * Marker interface. Every class that implements it, is signed as an elliptic curve point
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface ECElement extends GroupElement{
	
	
	/**
	 * This function returns the x coordinate of the (x,y) point which is an element of a given elliptic curve.
	 * In case of infinity point, returns null.
	 * @return x coordinate of (x,y) point
	 */
	public BigInteger getX();
	
	/**
	 * This function returns the y coordinate of the (x,y) point which is an element of a given elliptic curve.
	 * In case of infinity point, returns null.
	 * @return y coordinate of (x,y) point
	 */
	public BigInteger getY();
	
	/**
	 * Elliptic curve has a unique point called infinity.
	 * In order to know if this object is an infinity point, this function should be called.
	 * @return true if this point is the infinity, false, otherwise.
	 */
	public boolean isInfinity();
	
	
	
	
}
