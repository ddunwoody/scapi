/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


package edu.biu.scapi.primitives.dlog.bc;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.ECElementSendableData;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

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
	 * @return <code>true</code> if this element is the identity of the group; <code>false</code> otherwise.
	 */
	public boolean isIdentity(){

		return isInfinity();
	}
	
	public boolean isInfinity(){
		return point.isInfinity();
	}
	
	/**
	 * Two points are equal if they are both of type ECPointBc and their (x,y) coordinates are equal.
	 * 
	 */
	public boolean equals(Object elementToCompare){
		if (elementToCompare == null || elementToCompare.getClass() != this.getClass()) 
			return false;
	
		ECPointBc element = (ECPointBc) elementToCompare;
		if ((element.getX().compareTo(getX()) ==0) && (element.getY().compareTo(getY()) == 0)){
			return true;
		}
		
		return false;
	}
	/** 
	 * @see edu.biu.scapi.primitives.dlog.GroupElement#generateSendableData()
	 */
	@Override
	public GroupElementSendableData generateSendableData() {
		return new ECElementSendableData(getX(), getY());
	}
	
	@Override
	public String toString() {
		return "ECPointBc [point=" + getX()+"; " + getY() + "]";
	}
}
