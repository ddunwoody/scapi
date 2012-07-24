package edu.biu.scapi.primitives.dlog.miracl;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;

import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.ECFpPoint;
import edu.biu.scapi.primitives.dlog.ECFpUtility;
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
	 * Constructor that gets a x coordinates , calculates its corresponding y and set the point with these arguments
	 * @param x the x coordinate
	 * @param curve 
	 */
	ECFpPointMiracl(BigInteger x, MiraclDlogECFp curve){
		// This constructor does NOT guarantee that the created point is in the group. 
		// It creates a point on the curve, but this point is not necessarily a point in the dlog group, 
		// which is a sub-group of the elliptic curve.
		
		mip = curve.getMip();
		
		boolean validity[] = new boolean[1];
		
		//call for native function that creates random point in the field.
		point = createFpPointFromX(mip, x.toByteArray(), validity);
		
		//if the algorithm for random element failed - throws exception
		if(validity[0]==false){
			point = 0;
			throw new IllegalArgumentException("the given x has no corresponding y in the current curve");
		}
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
		return "ECFpPointMiracl [point= " + getX() + ", " + getY() + "]";
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
