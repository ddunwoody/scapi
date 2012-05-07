package edu.biu.scapi.primitives.dlog.miracl;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;

/**
 * This class is an adapter for Fp points of miracl
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECFpPointMiracl implements ECElement{

	private native long createFpPoint(long mip, byte[] x, byte[] y, boolean[] validity);
	private native long createFpPointFromX(long mip, byte[] x, boolean[] validity);
	private native long createRandomFpPoint(long mip, byte[] p, int seed, boolean[] validity);
	private native boolean checkInfinityFp(long point);
	private native void deletePointFp(long p);
	private native byte[] getXValueFpPoint(long mip, long point);
	private native byte[] getYValueFpPoint(long mip, long point);
	
	private long point = 0;
	private long mip = 0;
	
	/**
	 * Constructor that accepts x,y values of a point. 
	 * if the values are valid - set the point.
	 * @param x
	 * @param y
	 * @param curve - DlogGroup
	 */
	public ECFpPointMiracl(BigInteger x, BigInteger y, MiraclDlogECFp curve){
		mip = curve.getMip();
		
		boolean validity[] = new boolean[1];
		
		//call for a native function that creates an element in the field
		point = createFpPoint(mip, x.toByteArray(), y.toByteArray(), validity);
		
		//if the creation failed - throws exception
		if (validity[0]==false){
			point = 0;
			throw new IllegalArgumentException("x, y values are not a point on this curve");
		}	
	}
	
	/**
	 *  Constructor that gets DlogGroup and chooses a random point in the group
	 * @param curve
	 */
	public ECFpPointMiracl(MiraclDlogECFp curve){
		mip = curve.getMip();
		
		boolean validity[] = new boolean[1];
		
		//generates a seed to initiate the random number generator of miracl
		int seed = new BigInteger(new SecureRandom().generateSeed(20)).intValue();
		
		//call for native function that creates random point in the field.
		point = createRandomFpPoint(mip, 
							((ECFpGroupParams)curve.getGroupParams()).getP().toByteArray(), seed, validity);
		
		//if the algorithm for random element failed - throws exception
		if(validity[0]==false){
			point = 0;
			Logging.getLogger().log(Level.WARNING, "couldn't find random element");
		}
	}
	
	/**
	 * Constructor that gets a x coordinates , calculates its corresponding y and set the point with these arguments
	 * @param x the x coordinate
	 * @param curve 
	 */
	ECFpPointMiracl(BigInteger x, MiraclDlogECFp curve){
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
	
	public void release(){
		//delete from the dll the dynamic allocation of the point.
		deletePointFp(point);
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
