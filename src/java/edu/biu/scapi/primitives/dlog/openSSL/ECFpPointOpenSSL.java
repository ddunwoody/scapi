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
package edu.biu.scapi.primitives.dlog.openSSL;

import java.math.BigInteger;

import edu.biu.scapi.primitives.dlog.ECElementSendableData;
import edu.biu.scapi.primitives.dlog.ECFpPoint;
import edu.biu.scapi.primitives.dlog.ECFpUtility;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;

/**
 * This class is an adapter for Fp points of OpenSSL library.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECFpPointOpenSSL implements ECFpPoint{
	//Native functions that calls OpenSSL functionalities regarding the Fp points.
	private native long createPoint(long curve, byte[] x, byte[] y); 	//Creates the native point.
	private native byte[] getX(long curve, long point);					// Gets the x coordinate of the point.
	private native byte[] getY(long curve, long point);					// Gets the y coordinate of the point.
	private native boolean checkInfinity(long curve, long point);		// Checks if this point is the infinity. 
	private native void deletePoint(long point);						// Deletes the native point.
	
	private long point; //Pointer to the native point object.
	
	//For performance reasons we decided to keep redundant information about the point. Once we have the member long point which is a pointer
	//to the actual point generated in the native code we do not really have a need to keep the BigIntegers x and y, since this data can be retrieved 
	//from the point.
	//However, to retrieve these values we need to perform an extra JNI call for each one plus we need to create a new BigInteger each time. 
	//It follows that each time anywhere in the code the function ECFpPointOpenSSL::getX() gets called the following code would occur:
	//...
	//return new BigInteger(1, getX(curve, point));
	//This seems to be very wasteful performance-wise, so we decided to keep the redundant data here. We think that it is not that terrible since 
	//this class is immutable and once it is constructed there is not external way of re-setting the X and Y coordinates.
	private BigInteger x;
	private BigInteger y;
	
	/**
	 * Constructor that accepts x,y values of a point. 
	 * If the values are valid - set the point, else throw IllegalArgumentException.
	 * @param x the x coordinate of the candidate point
	 * @param y the y coordinate of the candidate point
	 * @param curve - DlogGroup
	 * @param bCheckMembership whether to check if (x,y) are a valid point on curve or not.
	 * @throws IllegalArgumentException if the (x,y) coordinates do not represent a valid point on the curve.
	 * 
	 */
	ECFpPointOpenSSL(BigInteger x, BigInteger y, OpenSSLDlogECFp curve, boolean bCheckMembership) throws IllegalArgumentException{
		if(bCheckMembership){
			//checks if the given parameters are valid point on the curve.
			boolean valid = new ECFpUtility().checkCurveMembership((ECFpGroupParams) curve.getGroupParams(), x, y);
			// checks validity
			if (valid == false) // if not valid, throws exception
				throw new IllegalArgumentException("x, y values are not a point on this curve");
		}
		//Create a point in the field with the given parameters, done by OpenSSL's native code.
		point = createPoint(curve.getCurve(), x.toByteArray(), y.toByteArray());
		//If the validity check done by OpenSSL did not succeed, then createFpPoint returns 0,
		//indicating that this is not a valid point
		if (point == 0)
			throw new IllegalArgumentException("x, y values are not a point on this curve");
		//Keep the coordinates for performance reasons. See long comment above next to declaration.
		this.x = x;
		this.y = y;
	}
	
	/**
	 * Constructor that gets an element and sets it. 
	 * Our inner functions only use this constructor to set an element. 
	 * The point is a result of our DlogGroup functions, such as multiply.
	 * @param point native element that need to be set.
	 */
	ECFpPointOpenSSL(long curve, long point) {
		this.point = point;
		
		if (checkInfinity(curve, point)){
			x = null;
			y = null;
		} else{
			//Set X and Y coordinates:
			//in case of infinity, there are no coordinates and we set them to null
			x = new BigInteger(1, getX(curve, point));
			y = new BigInteger(1, getY(curve, point));
		}
	}
	
	/**
	 * @return the pointer to the native point.
	 */
	long getPoint(){
		return point;
	}
	
	@Override
	public BigInteger getX() {
		return x;
	}

	@Override
	public BigInteger getY() {
		return y;
	}

	@Override
	public boolean isInfinity() {
		
		if ((x == null) && (y == null)){
			return true;
		} else{
			return false;
		}
	}

	@Override
	public boolean isIdentity() {
		return isInfinity();
	}

	@Override
	public GroupElementSendableData generateSendableData() {
		return new ECElementSendableData(getX(), getY());
	}
	
	/**
	 * Compares this Fp Point with elementToCompare.
	 * @return <code>true </code> if this (x,y) coordinates are equal to elementToCompare's (x,y) coordinates<p>
	 *  		<code>false </code>, otherwise
	 */
	public boolean equals(Object elementToCompare){
		if (!(elementToCompare instanceof ECFpPointOpenSSL)){
			return false;
		}
		ECFpPointOpenSSL element = (ECFpPointOpenSSL) elementToCompare;
		if ((element.getX().compareTo(getX()) ==0) && (element.getY().compareTo(getY()) == 0)){
			return true;
		}
		return false;
	}
	
	@Override
	public String toString() {
		return "ECFpPointOpenSSL [point= " + getX() + "; " + getY() + "]";
	}

	/**
	 * Delete the related point in OpenSSL's native code.
	 */
	protected void finalize() throws Throwable{
		//Delete from the dll the dynamic allocation of the point.
		deletePoint(point);
	}
}
