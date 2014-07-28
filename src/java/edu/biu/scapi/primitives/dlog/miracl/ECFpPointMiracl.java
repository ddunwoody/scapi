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


package edu.biu.scapi.primitives.dlog.miracl;

import java.math.BigInteger;

import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.ECElementSendableData;
import edu.biu.scapi.primitives.dlog.ECFpPoint;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

/**
 * This class is an adapter for Fp points of miracl
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECFpPointMiracl implements ECElement, ECFpPoint{

	private native long createFpPoint(long mip, byte[] x, byte[] y);
	private native boolean checkInfinityFp(long point);
	private native void deletePointFp(long p);
	private native byte[] getXValueFpPoint(long mip, long point);
	private native byte[] getYValueFpPoint(long mip, long point);
	
	private long point;
	//For performance reasons we decided to keep redundant information about the point. Once we have the member long point which is a pointer
	//to the actual point generated in the native code we do not really have a need to keep the BigIntegers x and y, since this data can be retrieved from the point.
	//However, to retrieve these values we need to perform an extra JNI call for each one plus we need to create a new BigInteger each time. It follows that each time
	//anywhere in the code the function ECFpPointMiracl::getX() gets called the following code would occur:
	//...
	//return new BigInteger(getXValueFpPoint(mip, point))
	//This seems to be very wasteful performance-wise, so we decided to keep the redundant data here. We think that it is not that terrible since this class is
	//immutable and once it is constructed there is not external way of re-setting the X and Y coordinates.
	private BigInteger x;
	private BigInteger y;
	private long mip;
	
	 
	/**
	 * Constructor that accepts x,y values of a point. 
	 * Miracl always checks validity of coordinates before creating the point.
	 * If the values are valid - set the point, else throw IllegalArgumentException.
	 * @param x the x coordinate of the candidate point
	 * @param y the y coordinate of the candidate point
	 * @param curve - DlogGroup
	 * @throws IllegalArgumentException if the (x,y) coordinates do not represent a valid point on the curve
	 * 
	 */
	ECFpPointMiracl(BigInteger x, BigInteger y, MiraclDlogECFp curve) throws IllegalArgumentException{
		mip = curve.getMip();
		
		//Create a point in the field with the given parameters, done by Miracl's native code.
		//Miracl always checks validity of (x,y).
		point = createFpPoint(mip, x.toByteArray(), y.toByteArray());
		//If the validity check done by Miracl did not succeed, then createF2mPoint returns 0,
		//indicating that this is not a valid point
		if (point == 0)
			throw new IllegalArgumentException("x, y values are not a point on this curve");
		//Keep the coordinates for performance reasons. See long comment above next to declaration.
		this.x = x;
		this.y = y;
	}
	
	/**
	 * Constructor that gets pointer to element and sets it.
	 * Only our inner functions use this constructor to set an element. 
	 * The ptr is a result of our DlogGroup functions, such as multiply.
	 * @param ptr - pointer to native point
	 */
	ECFpPointMiracl(long ptr, MiraclDlogECFp curve){
		this.point = ptr;
		mip = curve.getMip();
		//Set X and Y coordinates:
		//in case of infinity, there are no coordinates and we set them to null
		if (checkInfinityFp(ptr)){
			this.x = null;
			this.y = null;
		}else{
			this.x = new BigInteger(getXValueFpPoint(mip, point));
			this.y = new BigInteger(getYValueFpPoint(mip, point));
		}
			
	}
	
	public boolean isIdentity(){
		return isInfinity();
	}
	
	public boolean isInfinity(){
		return checkInfinityFp(point);
	}
	
	/**
	 * 
	 * @return the pointer to the point
	 */
	long getPoint(){
		return point;
	}
	
	public BigInteger getX(){
		return x;
	}
	
	public BigInteger getY(){
		return y;
	}
	
	/** 
	 * @see edu.biu.scapi.primitives.dlog.GroupElement#generateSendableData()
	 */
	@Override
	public GroupElementSendableData generateSendableData() {
		return new ECElementSendableData(getX(), getY());
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 17;
		int hashCodeX = getX().hashCode();
		int hashCodeY = getY().hashCode();
		result = prime * result + hashCodeX;
		result = prime * result + hashCodeY;
		return result;
	}
	
	/**
	 * Compares this Fp Point with elementToCompare.
	 * @return <code>true </code> if this (x,y) coordinates are equal to elementToCompare's (x,y) coordinates<p>
	 *  		<code>false </code>, otherwise
	 */
	public boolean equals(Object elementToCompare){
		if (!(elementToCompare instanceof ECFpPointMiracl)){
			return false;
		}
		ECFpPointMiracl element = (ECFpPointMiracl) elementToCompare;
		if ((element.getX().compareTo(getX()) ==0) && (element.getY().compareTo(getY()) == 0)){
			return true;
		}
		return false;
	}
	
	@Override
	public String toString() {
		return "ECFpPointMiracl [point= " + getX() + "; " + getY() + "]";
	}
	
	/**
	 * delete the related point in Miracl's native code.
	 */
	protected void finalize() throws Throwable{
		//delete from the dll the dynamic allocation of the point.
		deletePointFp(point);
	}
	
	
	static {
        System.loadLibrary("MiraclJavaInterface");
 }
}
