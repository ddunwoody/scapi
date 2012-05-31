package edu.biu.scapi.primitives.dlog.miracl;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.ECF2mPoint;
import edu.biu.scapi.primitives.dlog.ECF2mUtility;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
/**
 * This class is an adapter for F2m points of miracl
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECF2mPointMiracl implements ECElement, ECF2mPoint{
	/**
	 * 
	 */
	private static final long serialVersionUID = 5263481969362114289L;

	private native long createF2mPoint(long mip, byte[] x, byte[] y);
	private native long createF2mPointFromX(long mip, byte[] x, boolean[] validity);
	private native long createRandomF2mPoint(long mip, int m, int seed, boolean[] validity);
	private native boolean checkInfinityF2m(long point);
	private native byte[] getXValueF2mPoint(long mip, long point);
	private native byte[] getYValueF2mPoint(long mip, long point);
	private native void deletePointF2m(long p);
	
	private long point = 0;
	private long mip = 0;
	private String curveName;
	private String fileName;
	
	private ECF2mUtility util = new ECF2mUtility();
	/**
	 * Constructor that accepts x,y values of a point. 
	 * if the values are valid - set the point.
	 * @param x
	 * @param y
	 * @param curve - DlogGroup
	 */
	public ECF2mPointMiracl(BigInteger x, BigInteger y, MiraclDlogECF2m curve){
		
		mip = curve.getMip();
		curveName = curve.getCurveName();
		fileName = curve.getFileName();

		boolean valid = util.checkCurveMembership((ECF2mGroupParams) curve.getGroupParams(), x, y);
		// checks validity
		if (valid == false) // if not valid, throws exception
			throw new IllegalArgumentException("x, y values are not a point on this curve");
		
		//creates a point in the field with the given parameters
		point = createF2mPoint(mip, x.toByteArray(), y.toByteArray());
	
	}
	
	/**
	 * Constructor that gets a x coordinates , calculates its corresponding y and set the point with these arguments
	 * @param x the x coordinate
	 * @param curve
	 */
	ECF2mPointMiracl(BigInteger x, MiraclDlogECF2m curve){
		// This constructor is NOT guarantee that the created point is in the group. 
		// It creates a point on the curve, but this point is not necessarily a point in the dlog group, 
		// which is a sub-group of the elliptic curve.
				
		mip = curve.getMip();
		curveName = curve.getCurveName();
		fileName = curve.getFileName();
		
		boolean validity[] = new boolean[1];
		
		//call for native function that creates random point in the field.
		point = createF2mPointFromX(mip, x.toByteArray(), validity);
		
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
	ECF2mPointMiracl(long ptr, MiraclDlogECF2m curve){
		this.point = ptr;
		mip = curve.getMip();
		curveName = curve.getCurveName();
		fileName = curve.getFileName();
	}
	
	private void writeObject(ObjectOutputStream out) throws IOException{ 
		out.writeObject(curveName); 
		out.writeObject(fileName);
		byte[] x = getXValueF2mPoint(mip, point);
		byte[] y = getYValueF2mPoint(mip, point);
		out.writeObject(x);
		out.writeObject(y);
	}
	
	private void readObject(ObjectInputStream in) throws IOException { 
		byte [] x = null, y = null;
		try {
			curveName = (String) in.readObject();
			fileName = (String) in.readObject();
			x = (byte[]) in.readObject();
			y = (byte[]) in.readObject();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		MiraclDlogECF2m dlog = new MiraclDlogECF2m(fileName, curveName);
		
		boolean valid = util.checkCurveMembership((ECF2mGroupParams) dlog.getGroupParams(), new BigInteger(x), new BigInteger(y));
		// checks validity
		if (valid == false) // if not valid, throws exception
			throw new IllegalArgumentException("x, y values are not a point on this curve");
		
		mip = dlog.getMip();
		point = createF2mPoint(mip, x, y);
	}
	
	/**
	 * 
	 * @return the pointer to the point
	 */
	long getPoint(){
		return point;
	}
	
	public boolean isIdentity(){
		return isInfinity();
	}
	
	public boolean isInfinity(){
		return checkInfinityF2m(point);
	}
	
	public BigInteger getX(){
		//in case of infinity, there is no coordinates and returns null
		if (isInfinity()){
			return null;
		}
		
		return new BigInteger(getXValueF2mPoint(mip, point));
	}
	
	public BigInteger getY(){
		//in case of infinity, there is no coordinates and returns null
		if (isInfinity()){
			return null;
		}
		
		return new BigInteger(getYValueF2mPoint(mip, point));
	}
	
	public boolean equals(Object elementToCompare){
		if (!(elementToCompare instanceof ECF2mPointMiracl)){
			return false;
		}
		ECF2mPointMiracl element = (ECF2mPointMiracl) elementToCompare;
		if ((element.getX().compareTo(getX()) ==0) && (element.getY().compareTo(getY()) == 0)){
			return true;
		}
		return false;
	}
	
	/**
	 * delete the related point
	 */
	protected void finalize() throws Throwable{
		
		//delete from the dll the dynamic allocation of the point.
		deletePointF2m(point);
	}
	
	static {
        System.loadLibrary("MiraclJavaInterface");
	}

}
