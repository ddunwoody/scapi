package edu.biu.scapi.primitives.dlog.bc;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

import edu.biu.scapi.primitives.dlog.ECElement;

/**
 * This class is an adapter for BC point.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class ECPointBc implements ECElement{

	protected ECPoint point = null;
	
	
	ECPoint getPoint(){
		return point;
	}

	public BigInteger getX(){
		//in case of infinity, there is no coordinates and returns null
		if (isInfinity()){
			return null;
		}
		
		return point.getX().toBigInteger();
	}
	
	public BigInteger getY(){
		//in case of infinity, there is no coordinates and returns null
		if (isInfinity()){
			return null;
		}
		
		return point.getY().toBigInteger();
	}
	
	/**
	 * checks if the element is the identity of this Dlog group.
	 * @return <code>true<code> if this element is the identity of the group; <code>false<code> otherwise.
	 */
	public boolean isIdentity(){

		return isInfinity();
	}
	
	public boolean isInfinity(){
		return point.isInfinity();
	}
	
	public boolean equals(Object elementToCompare){
		if (elementToCompare == null || elementToCompare.getClass() != this.getClass()) 
			return false;
	
		ECPointBc element = (ECPointBc) elementToCompare;
		if ((element.getX().compareTo(getX()) ==0) && (element.getY().compareTo(getY()) == 0)){
			return true;
		}
		
		return false;
	}
}
