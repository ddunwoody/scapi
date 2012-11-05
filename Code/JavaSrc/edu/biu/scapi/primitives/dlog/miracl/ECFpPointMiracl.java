/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
package edu.biu.scapi.primitives.dlog.miracl;

import java.math.BigInteger;

import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.ECElementSendableData;
import edu.biu.scapi.primitives.dlog.ECFpPoint;
import edu.biu.scapi.primitives.dlog.ECFpUtility;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;

/**
 * This class is an adapter for Fp points of miracl
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECFpPointMiracl implements ECElement, ECFpPoint{

	private native long createFpPoint(long mip, byte[] x, byte[] y);
	private native long createFpPointFromX(long mip, byte[] x, boolean[] validity);
	private native long createRandomFpPoint(long mip, byte[] p, int seed, boolean[] validity);
	private native boolean checkInfinityFp(long point);
	private native void deletePointFp(long p);
	private native byte[] getXValueFpPoint(long mip, long point);
	private native byte[] getYValueFpPoint(long mip, long point);
	
	private long point;
	private long mip;
	
	private ECFpUtility util;
	 
	/**
	 * Constructor that accepts x,y values of a point. 
	 * if the values are valid - set the point.
	 * @param x
	 * @param y
	 * @param curve - DlogGroup
	 */
	ECFpPointMiracl(BigInteger x, BigInteger y, MiraclDlogECFp curve) throws IllegalArgumentException{
		mip = curve.getMip();
		util = new ECFpUtility();
		boolean valid = util.checkCurveMembership((ECFpGroupParams) curve.getGroupParams(), x, y);
		// checks validity
		if (valid == false) // if not valid, throws exception
			throw new IllegalArgumentException("x, y values are not a point on this curve");


		//call for a native function that creates an element in the field
		point = createFpPoint(mip, x.toByteArray(), y.toByteArray());
			
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
		//in case of infinity, there is no coordinates and returns null
		if (isInfinity()){
			return null;
		}
		
		return new BigInteger(getXValueFpPoint(mip, point));
		
	}
	
	public BigInteger getY(){
		//in case of infinity, there is no coordinates and returns null
		if (isInfinity()){
			return null;
		}
		
		return new BigInteger(getYValueFpPoint(mip, point));
		
	}
	
	/** 
	 * @see edu.biu.scapi.primitives.dlog.GroupElement#generateSendableData()
	 */
	@Override
	public GroupElementSendableData generateSendableData() {
		return new ECElementSendableData(getX(), getY());
	}
	
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
	 * delete the related point
	 */
	protected void finalize() throws Throwable{
		
		//delete from the dll the dynamic allocation of the point.
		deletePointFp(point);
	}
	
	
	static {
        System.loadLibrary("MiraclJavaInterface");
 }
}
