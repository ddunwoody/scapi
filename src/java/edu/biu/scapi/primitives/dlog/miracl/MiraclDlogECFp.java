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

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Properties;

import edu.biu.scapi.primitives.dlog.DlogECFp;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.ECFpUtility;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;
import edu.biu.scapi.securityLevel.DDH;

/**
 * This class implements an Elliptic curve Dlog group over Zp utilizing Miracl's implementation.<p>
 * It uses JNI technology to call Miracl's native code.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public class MiraclDlogECFp extends MiraclAdapterDlogEC implements DlogECFp, DDH{	
	// upload MIRACL library
	static {
		System.loadLibrary("MiraclJavaInterface");
	}

	private native void initFpCurve(long mip, byte[] p, byte[] a,byte[] b);
	private native long multiplyFpPoints(long mip, long p1, long p2);
	private native long simultaneousMultiplyFp(long mip, long[] points, byte[][] exponents);
	private native long exponentiateFpPoint(long mip, long p, byte[] exponent);
	private native long invertFpPoint(long mip, long p);
	private native boolean validateFpGenerator(long mip, long generator, byte[] x, byte[] y);
	private native boolean isFpMember(long mip, long point);
	private native long createInfinityFpPoint(long mip);
	private native long initFpExponentiateWithPrecomputedValues(long mip,byte[]p, byte[]a, byte[]b, long base, byte[] exponent, int window, int maxBits);
	private native long computeFpExponentiateWithPrecomputedValues(long mip, long ebrickPointer, byte[] exponent);
	private native void endFpExponentiateWithPreComputedValues(long ebrickPointer);	
	//Encodes the given byte array into a point. If the given byte array can not be encoded to a point, returns 0.
	private native long encodeByteArrayToPoint(long mip, byte[] binaryString, int k);
	
	private ECFpUtility util;
	
	/**
	 * Default constructor. Initializes this object with P-192 NIST curve.
	 */
	public MiraclDlogECFp() throws IOException {
		this("P-192");
	}

	public MiraclDlogECFp(String fileName, String curveName) throws IOException {
		super(fileName, curveName);
	}
	
	public MiraclDlogECFp(String fileName, String curveName, String randNumGenAlg) throws IOException, NoSuchAlgorithmException {
		super(fileName, curveName, SecureRandom.getInstance(randNumGenAlg));
	}

	public MiraclDlogECFp(String curveName) throws IllegalArgumentException, IOException{
		this(NISTEC_PROPERTIES_FILE, curveName);
	}
	
	public MiraclDlogECFp(String curveName, SecureRandom random) throws IllegalArgumentException, IOException{
		super(NISTEC_PROPERTIES_FILE, curveName, random);
	}

	/**
	 * Extracts the parameters of the curve from the properties object and initialize the groupParams, 
	 * generator and the underlying curve
	 * @param ecProperties - properties object contains the curve file data
	 * @param curveName - the curve name as it called in the file
	 */
	protected void doInit(Properties ecProperties, String curveName) {
		util = new ECFpUtility();
		groupParams = util.checkAndCreateInitParams(ecProperties, curveName);
		//Now that we have p, we can calculate k which is the maximum length in bytes of a string to be converted to a Group Element of this group. 
		BigInteger p = ((ECFpGroupParams)groupParams).getP();
		k = util.calcK(p);	
		createUnderlyingCurveAndGenerator(groupParams);
	}
	
	private void createUnderlyingCurveAndGenerator(GroupParams params){
		//There is no need to check that the params passed are an instance of ECFpGroupParams since this function is only used by SCAPI.
		ECFpGroupParams fpParams = (ECFpGroupParams)params;
		// create the ECCurve
		BigInteger p = fpParams.getP();
		initFpCurve(getMip(), p.toByteArray(), fpParams.getA().mod(p).toByteArray(), fpParams.getB().toByteArray());
		// create the generator
		generator = new ECFpPointMiracl(fpParams.getXg(), fpParams.getYg(), this);
	}
	
	
	/**
	 * @return the type of the group - ECFp
	 */
	public String getGroupType() {
		return util.getGroupType();
	}

	/**
	 * Calculate the inverse of the given GroupElement
	 * @param groupElement to inverse
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 */
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException{
		
		//if the GroupElement doesn't match the DlogGroup, throw exception
		if (!(groupElement instanceof ECFpPointMiracl)){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}

		// the inverse of infinity point is infinity
		if (((ECFpPointMiracl) groupElement).isInfinity()) {
			return groupElement;
		}

		long point = ((ECFpPointMiracl) groupElement).getPoint();
		// call the native inverse function
		long result = invertFpPoint(mip, point);
		// build a ECFpPointMiracl element from the result value
		return new ECFpPointMiracl(result, this);

	}

	/**
	 * Multiply two GroupElements
	 * @param groupElement1
	 * @param groupElement2
	 * @return the multiplication result
	 * @throws IllegalArgumentException
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1,
						GroupElement groupElement2) throws IllegalArgumentException {

		// if the GroupElements don't match the DlogGroup, throw exception
		if (!(groupElement1 instanceof ECFpPointMiracl)) {
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}
		if (!(groupElement2 instanceof ECFpPointMiracl)){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}

		//if one of the points is the infinity point, the second one is the multiplication result
		if (((ECFpPointMiracl) groupElement1).isInfinity()) {
			return groupElement2;
		}
		if (((ECFpPointMiracl) groupElement2).isInfinity()) {
			return groupElement1;
		}

		long point1 = ((ECFpPointMiracl) groupElement1).getPoint();
		long point2 = ((ECFpPointMiracl) groupElement2).getPoint();

		// call the native multiply function
		long result = multiplyFpPoints(mip, point1, point2);
		// build a ECFpPointMiracl element from the result value
		return new ECFpPointMiracl(result, this);

	}

	/**
	 * Calculate the exponentiate of the given GroupElement
	 * @param exponent
	 * @param base
	 * @return the result of the exponentiation
	 * @throws IllegalArgumentException
	 */
	public GroupElement exponentiate(GroupElement base, BigInteger exponent)
									throws IllegalArgumentException {

		// if the GroupElements don't match the DlogGroup, throw exception
		if (!(base instanceof ECFpPointMiracl)) {
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}

		// infinity remains the same after any exponentiate
		if (((ECFpPointMiracl) base).isInfinity()) {
			return base;
		}

		//If the exponent is negative, convert it to be the exponent modulus q.
		if (exponent.compareTo(BigInteger.ZERO) < 0){
			exponent = exponent.mod(getOrder());
		}
				
		long point = ((ECFpPointMiracl) base).getPoint();
		// call the native exponentiate function
		long result = exponentiateFpPoint(mip, point, exponent.toByteArray());
		// build a ECFpPointMiracl element from the result value
		return new ECFpPointMiracl(result, this);

	}

	/**
	 * Computes the product of several exponentiations with distinct bases 
	 * and distinct exponents. 
	 * Instead of computing each part separately, an optimization is used to 
	 * compute it simultaneously. 
	 * @param groupElements
	 * @param exponentiations
	 * @return the exponentiation result
	 */
	@Override
	public GroupElement simultaneousMultipleExponentiations(GroupElement[] groupElements, 
			BigInteger[] exponentiations) {
		
		int len = groupElements.length;
		
		//Our test results show that for elliptic curve over Fp and n<25 the naive algorithm gives the best performances
		if (len < 25) {
			return computeNaive(groupElements, exponentiations);
		}

		long[] nativePoints = new long[len];
		byte[][] exponents = new byte[len][];
		for (int i = 0; i < len; i++) {
			// if the GroupElements don't match the DlogGroup, throw exception
			if (!(groupElements[i] instanceof ECFpPointMiracl)) {
				throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
			}
			nativePoints[i] = ((ECFpPointMiracl) groupElements[i]).getPoint();
			exponents[i] = exponentiations[i].toByteArray();
		}

		// call the native simultaneousMultiplyFp function
		long result = simultaneousMultiplyFp(mip, nativePoints, exponents);
		// build a ECF2mPointMiracl element from the result value
		return new ECFpPointMiracl(result, this);
	}

	
	/**
	 * @deprecated As of SCAPI-V2_0_0 use generateElment(boolean bCheckMembership, BigInteger...values)
	 */
	@Deprecated public ECElement generateElement(BigInteger x, BigInteger y) throws IllegalArgumentException{
		//Creates element with the given values.
		ECFpPointMiracl point =  new ECFpPointMiracl(x, y, this);
		
		//if the element was created, it is a point on the curve.
		//checks if the point is in the sub-group, too.
		boolean valid = util.checkSubGroupMembership(this, point);
		
		//if the point is not in the sub-group, throw exception.
		if (valid == false){
			throw new IllegalArgumentException("Could not generate the element. The given (x, y) is not a point in this Dlog group");
		}
		
		return point;
	}
	
	
	/**
	 * This function generates a Group Element on this curve given the (x,y) values, if and only if the values are valid. Meaning that 
	 * this function always checks validity since the actual creation of the point is performed by Miracl's native code and  
	 * in the case of Miracle the validity of the (x, y) values is always checked. Therefore, even if this function is called
	 * with bCheckMembership set to FALSE the validity check is performed.
	 * @param bCheckMembership disregard this parameter, this function ALWAYS checks membership
	 * @param values x and y coordinates of the requested point
	 * @throws IllegalArgumentException if the number of elements of the values parameter is not 2 and/or
	 * 								   if (x,y) do not represent a valid point on the curve 	
	 * @see edu.biu.scapi.primitives.dlog.DlogGroup#generateElement(boolean, java.math.BigInteger[])
	 */
	@Override
	public GroupElement generateElement(boolean bCheckMembership, BigInteger... values) throws IllegalArgumentException {
		if(values.length != 2){
			throw new IllegalArgumentException("To generate an ECElement you should pass the x and y coordinates of the point");
		}
		return new ECFpPointMiracl(values[0], values[1], this);
	}

	/**
	 * Checks if the given element is member of that Dlog group
	 * @param element - 
	 * @return true if the given element is member of that group. false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) {

		// checks that the element is the correct object
		if (!(element instanceof ECFpPointMiracl)) {
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}

		ECFpPointMiracl point = (ECFpPointMiracl) element;
		// infinity point is a valid member
		if (point.isInfinity()) {
			return true;
		}

		// A point (x, y) is a member of a Dlog group with prime order q over an Elliptic Curve if it meets the following two conditions:
		// 1)	P = (x,y) is a point in the Elliptic curve, i.e (x,y) is a solution of the curve’s equation.
		// 2)	P = (x,y) is a point in the q-order group which is a sub-group of the Elliptic Curve.
		// those two checks are done in two steps:
		// 1.	Checking that the point is on the curve, performed by checkCurveMembership
		// 2.	Checking that the point is in the Dlog group,performed by checkSubGroupMembership

		
		//The actual work is implemented in ECFpUtility since it is independent of the underlying library (BC, Miracl, or other)
		//If we ever decide to change the implementation there will only be one place to change it.
		boolean valid = util.checkCurveMembership((ECFpGroupParams) groupParams, point.getX(), point.getY());
		valid = valid && util.checkSubGroupMembership(this, point);
		
		return valid;
	}

	public ECElement getInfinity() {
		long infinity = createInfinityFpPoint(mip);
		return new ECFpPointMiracl(infinity, this);
	}


	/**
	 * This function takes any string of length up to k bytes and encodes it to a Group Element. 
	 * k can be obtained by calling getMaxLengthOfByteArrayForEncoding() and it is calculated upon construction of this group; it depends on the length in bits of p.<p>
	 * The encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but is not onto. 
	 * Therefore, any string of length in bytes up to k can be encoded to a group element but not every group element can be decoded to a binary string in the group of binary strings of length up to 2^k.<p>
	 * Thus, the right way to use this functionality is first to encode a byte array and then to decode it, and not the opposite.
	 * 
	 * @param binaryString the byte array to convert
	 * @throws IndexOutOfBoundsException if the length of the binary array to encode is longer than k
	 * @return the created group Element or null if could not find the encoding in reasonable time
	 */
	public GroupElement encodeByteArrayToGroupElement(byte[] binaryString) {
		
		long point = encodeByteArrayToPoint(mip, binaryString, k);
		
		if (point == 0)
			return null;
		
		 // Build a ECFpPointOpenSSL element from the result.
		return new ECFpPointMiracl(point, this);
	}
	
	/**
	 * This function decodes a group element to a byte array. This function is guaranteed to work properly ONLY if the group element was obtained as a result of 
	 * encoding a binary string of length in bytes up to k.<p>
	 * This is because the encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but is not onto. 
	 * Therefore, any string of length in bytes up to k can be encoded to a group element but not any group element can be decoded 
	 * to a binary sting in the group of binary strings of length up to 2^k.
	 * 
	 * @param groupElement the element to convert
	 * @return the created byte array
	 */
	public byte[] decodeGroupElementToByteArray(GroupElement groupElement) {
		if (!(groupElement instanceof ECFpPointMiracl)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		ECFpPointMiracl point = (ECFpPointMiracl) groupElement;
		byte[] xByteArray = point.getX().toByteArray();
		byte bOriginalSize = xByteArray[xByteArray.length -1];
		byte[] b2 = new byte[bOriginalSize];
		System.arraycopy(xByteArray,xByteArray.length -1  -  bOriginalSize, b2, 0, bOriginalSize);
		return b2;
	}
	
	/**
	 * This function maps a group element of this dlog group to a byte array.<p>
	 * This function does not have an inverse function, that is, it is not possible to re-construct the original group element from the resulting byte array. 
	 * @return a byte array representation of the given group element
	 */
	public byte[] mapAnyGroupElementToByteArray(GroupElement groupElement) {
		//This function simply returns an array which is the result of concatenating 
		//the byte array representation of x with the byte array representation of y.
		if (!(groupElement instanceof ECFpPointMiracl)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		ECFpPointMiracl point = (ECFpPointMiracl) groupElement;
		//The actual work is implemented in ECFpUtility since it is independent of the underlying library (BC, Miracl, or other)
		//If we ever decide to change the implementation there will only be one place to change it.
		return util.mapAnyGroupElementToByteArray(point.getX(), point.getY());
	}

	@Override
	public void endExponentiateWithPreComputedValues(GroupElement base){
		Long ebrickPointer = exponentiationsMap.remove(base);
		if (ebrickPointer != null){
			endFpExponentiateWithPreComputedValues(ebrickPointer);
		}
	}

	
	/* (non-Javadoc)
	 * @see edu.biu.scapi.primitives.dlog.miracl.MiraclAdapterDlogEC#basicAndInfinityChecksForExpForPrecomputedValues()
	 */
	@Override
	protected boolean basicAndInfinityChecksForExpForPrecomputedValues(GroupElement base) {
	
		// if the GroupElements does not match the DlogGroup, throw exception
		if (!(base instanceof ECFpPointMiracl)) {
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}

		ECFpPointMiracl baseECFp = (ECFpPointMiracl) base;

		// infinity remains the same after any exponentiate
		return baseECFp.isInfinity();				
	}
	
	/* (non-Javadoc)
	 * returns a pointer to newly created Ebrick structure in Miracl's native code.
	 * @see edu.biu.scapi.primitives.dlog.miracl.MiraclAdapterDlogEC#initExponentiateWithPrecomputedValues(edu.biu.scapi.primitives.dlog.GroupElement, java.math.BigInteger, int, int)
	 */
	@Override
	protected long initExponentiateWithPrecomputedValues(GroupElement baseElement, BigInteger exponent, int window, int maxBits) {
		
		ECFpGroupParams params = (ECFpGroupParams) getGroupParams();
		return initFpExponentiateWithPrecomputedValues(mip, params.getP().toByteArray(), params.getA().mod(params.getP()).toByteArray(), params.getB().toByteArray(),
				((ECFpPointMiracl)baseElement).getPoint() ,exponent.toByteArray(), window, maxBits);
	}
	/* (non-Javadoc)
	 * actually compute the exponentiation in Miracl's native code using the previously created and computed Ebrick structure. The native function returns a pointer
	 * to the computed result and this function converts it to the right GroupElement. 
	 * @see edu.biu.scapi.primitives.dlog.miracl.MiraclAdapterDlogEC#computeExponentiateWithPrecomputedValue(long, java.math.BigInteger)
	 */
	@Override
	protected GroupElement computeExponentiateWithPrecomputedValues(	long ebrickPointer, BigInteger exponent) {
		//Perform the calculation in the native code
		long result = computeFpExponentiateWithPrecomputedValues(mip, ebrickPointer, exponent.toByteArray());
		
		//Build a ECFpPointMiracl element from the result value
		return new ECFpPointMiracl(result, this);
	}
	
}


