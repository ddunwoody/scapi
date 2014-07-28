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
import edu.biu.scapi.securityLevel.DDH;

/**
 * This class implements an Elliptic curve Dlog group over Fp utilizing OpenSSL's implementation. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OpenSSLDlogECFp extends OpenSSLAdapterDlogEC implements DlogECFp, DDH{
	
	private ECFpUtility util; //Utility class that computes some common ECFp functionalities.
	
	//Creates the native curve.
	private native long createCurve(byte[] p, byte[] a, byte[] b);
	//Initializes the native curve with the generator and order.
	private native int initCurve(long curve, long generator, byte[] q);
	//Encodes the given byte array into a point. If the given byte array can not be encoded to a point, returns 0.
	private native long encodeByteArrayToPoint(long curve, byte[] binaryString, int k);
	
	/**
	 * Default constructor. Initializes this object with P-192 NIST curve.
	 * @throws IOException 
	 */
	public OpenSSLDlogECFp() throws IOException {
		this("P-192");
	}
	
	/**
	 * Initialize this DlogGroup with the curve in the given file.
	 * @param fileName the file to take the curve's parameters from.
	 * @param curveName name of curve to initialized.
	 * @throws IOException if there is a problem with the given file name.
	 */
	public OpenSSLDlogECFp(String fileName, String curveName) throws IOException {
		super(fileName, curveName);	
	}
	
	/**
	 * Initialize this DlogGroup with the curve in the given file.
	 * @param fileName the file to take the curve's parameters from.
	 * @param curveName name of curve to initialized.
	 * @param randNumGenAlg The random number generator to use.
	 * @throws IOException if there is a problem with the given file name.
	 * @throws NoSuchAlgorithmException 
	 */
	public OpenSSLDlogECFp(String fileName, String curveName, String randNumGenAlg) throws IOException, NoSuchAlgorithmException {
		super(fileName, curveName, SecureRandom.getInstance(randNumGenAlg));	
	}
	
	/**
	 * Initialize this DlogGroup with one of NIST recommended elliptic curve.
	 * @param curveName name of NIST curve to initialized
	 * @throws IOException if there is a problem with NIST properties file.
	 */
	public OpenSSLDlogECFp(String curveName) throws IOException {
		super(curveName);
	}
	
	/**
	 * Initialize this DlogGroup with one of NIST recommended elliptic curve.
	 * @param curveName name of NIST curve to initialized
	 * @param random The source of randomness to use.
	 * @throws IOException if there is a problem with NIST properties file.
	 */
	public OpenSSLDlogECFp(String curveName, SecureRandom random) throws IOException {
		super(curveName, random);
	}
	
	@Override
	protected void doInit(Properties ecProperties, String curveName) {
		util = new ECFpUtility();
		groupParams = util.checkAndCreateInitParams(ecProperties, curveName);
		
		//There is no need to check that the params passed are an instance of ECFpGroupParams since this function is only used by SCAPI.
		ECFpGroupParams fpParams = (ECFpGroupParams)groupParams;
		BigInteger p = fpParams.getP();
		//Now that we have p, we can calculate k which is the maximum length in bytes of a string to be converted to a Group Element of this group. 
		k = util.calcK(p);	
		
		// Create the ECCurve.
		curve = createCurve(p.toByteArray(), fpParams.getA().mod(p).toByteArray(), fpParams.getB().toByteArray());
		
		// Create the generator.
		generator  = new ECFpPointOpenSSL(fpParams.getXg(), fpParams.getYg(), this, true);
		
		//Initialize the curve with the generator and order.
		initCurve(curve, ((ECFpPointOpenSSL) generator).getPoint(), fpParams.getQ().toByteArray());
	}

	@Override
	public ECElement getInfinity() {
		//Create an infinity point and return it.
		long infinity = createInfinityPoint(curve);
		return new ECFpPointOpenSSL(curve, infinity);
	}

	/**
	 * @return the type of the group - ECFp.
	 */
	public String getGroupType() {
		return util.getGroupType();
	}


	@Override
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException {
		//If the GroupElement doesn't match the DlogGroup, throw exception.
		if (!(groupElement instanceof ECFpPointOpenSSL)){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}

		// The inverse of infinity point is infinity.
		if (((ECFpPointOpenSSL) groupElement).isInfinity()) {
			return groupElement;
		}

		long point = ((ECFpPointOpenSSL) groupElement).getPoint();
		// Call the native inverse function.
		long result = inversePoint(curve, point);
		// Build a ECFpPointOpenSSL element from the result.
		return new ECFpPointOpenSSL(curve, result);
	}

	@Override
	public GroupElement exponentiate(GroupElement base, BigInteger exponent)
			throws IllegalArgumentException {
		//If the GroupElement doesn't match the DlogGroup, throw exception.
		if (!(base instanceof ECFpPointOpenSSL)){
			throw new IllegalArgumentException("the given base doesn't match the DlogGroup");
		}

		// The inverse of infinity point is infinity.
		if (((ECFpPointOpenSSL) base).isInfinity()) {
			return base;
		}

		//If the exponent is negative, convert it to be the exponent modulus q.
		if (exponent.compareTo(BigInteger.ZERO) < 0){
			exponent = exponent.mod(getOrder());
		}
				
		long point = ((ECFpPointOpenSSL) base).getPoint();
		// Call the native exponentiate function.
		long result = exponentiate(curve, point, exponent.toByteArray());
		// Build a ECFpPointOpenSSL element from the result.
		return new ECFpPointOpenSSL(curve, result);
	}

	@Override
	public GroupElement multiplyGroupElements(GroupElement groupElement1, GroupElement groupElement2) throws IllegalArgumentException {
		// If the GroupElements don't match the DlogGroup, throw exception.
		if (!(groupElement1 instanceof ECFpPointOpenSSL)) {
			throw new IllegalArgumentException("the first group element doesn't match the DlogGroup");
		}
		if (!(groupElement2 instanceof ECFpPointOpenSSL)){
			throw new IllegalArgumentException("the second group element doesn't match the DlogGroup");
		}

		//If one of the points is the infinity point, the second one is the multiplication result.
		if (((ECFpPointOpenSSL) groupElement1).isInfinity()) {
			return groupElement2;
		}
		if (((ECFpPointOpenSSL) groupElement2).isInfinity()) {
			return groupElement1;
		}

		long point1 = ((ECFpPointOpenSSL) groupElement1).getPoint();
		long point2 = ((ECFpPointOpenSSL) groupElement2).getPoint();

		// Call the native multiply function.
		long result = multiply(curve, point1, point2);
		// Build a ECFpPointOpenSSL element from the result.
		return new ECFpPointOpenSSL(curve, result);

	}

	@Override
	public boolean isMember(GroupElement element) throws IllegalArgumentException {
		// Checks that the element is the correct object.
		if (!(element instanceof ECFpPointOpenSSL)) {
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}

		ECFpPointOpenSSL point = (ECFpPointOpenSSL) element;
		// Infinity point is a valid member.
		if (point.isInfinity()) {
			return true;
		}

		// A point (x, y) is a member of a Dlog group with prime order q over an Elliptic Curve if it meets the following two conditions:
		// 1)	P = (x,y) is a point in the Elliptic curve, i.e (x,y) is a solution of the curve’s equation.
		// 2)	P = (x,y) is a point in the q-order group which is a sub-group of the Elliptic Curve.
		// Those two checks are done in two steps:
		// 1.	Checking that the point is on the curve, performed by checkCurveMembership.
		// 2.	Checking that the point is in the Dlog group,performed by checkSubGroupMembership.

		//The first check is done by the native library.
		boolean valid = checkCurveMembership(curve, point.getPoint());
		//The second check is implemented in ECFpUtility since it is independent of the underlying library (BC, Miracl, or other)
		//If we ever decide to change the implementation there will only be one place to change it.
		valid = valid && util.checkSubGroupMembership(this, point);
		
		return valid;
	}
	
	@Override
	public GroupElement generateElement(boolean bCheckMembership, BigInteger... values) throws IllegalArgumentException {
		if(values.length != 2){
			throw new IllegalArgumentException("To generate an ECElement you should pass the x and y coordinates of the point");
		}
		return new ECFpPointOpenSSL(values[0], values[1], this, bCheckMembership);
	}

	@Override
	public GroupElement simultaneousMultipleExponentiations(GroupElement[] groupElements, BigInteger[] exponentiations) {
		
		int len = groupElements.length;

		//Create arrays to hold the native points and the exponents' bytes.
		long[] nativePoints = new long[len];
		byte[][] exponents = new byte[len][];
		for (int i = 0; i < len; i++) {
			// if the GroupElements don't match the DlogGroup, throw exception.
			if (!(groupElements[i] instanceof ECFpPointOpenSSL)) {
				throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
			}
			nativePoints[i] = ((ECFpPointOpenSSL) groupElements[i]).getPoint();
			exponents[i] = exponentiations[i].toByteArray();
		}

		// Call the native simultaneousMultiply function.
		long result = simultaneousMultiply(curve, nativePoints, exponents);
		// Build a ECFpPointOpenSSL element from the result value.
		return new ECFpPointOpenSSL(curve, result);
	}

	@Override
	public GroupElement encodeByteArrayToGroupElement(byte[] binaryString) {
		//Call a native function that encode the byte array to a point.
		long point = encodeByteArrayToPoint(curve, binaryString, k);
		
		//If failed to create a point, return null.
		if (point == 0)
			return null;
		
		 // Build a ECFpPointOpenSSL element from the result.
		return new ECFpPointOpenSSL(curve, point);
	}

	@Override
	public byte[] decodeGroupElementToByteArray(GroupElement groupElement) {
		// Checks that the element is the correct object.
		if (!(groupElement instanceof ECFpPointOpenSSL)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		ECFpPointOpenSSL point = (ECFpPointOpenSSL) groupElement;
		byte[] xByteArray = point.getX().toByteArray();
		//The original size is placed in the last byte of x.
		byte bOriginalSize = xByteArray[xByteArray.length -1];
		byte[] b2 = new byte[bOriginalSize];
		
		//Copy the original byte array.
		System.arraycopy(xByteArray, xByteArray.length -1  -  bOriginalSize, b2, 0, bOriginalSize);
		return b2;
	}

	@Override
	public byte[] mapAnyGroupElementToByteArray(GroupElement groupElement) {
		//This function simply returns an array which is the result of concatenating 
		//the byte array representation of x with the byte array representation of y.
		if (!(groupElement instanceof ECFpPointOpenSSL)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		ECFpPointOpenSSL point = (ECFpPointOpenSSL) groupElement;
		
		//The actual work is implemented in ECFpUtility since it is independent of the underlying library (BC, Miracl, or other)
		//If we ever decide to change the implementation there will only be one place to change it.
		return util.mapAnyGroupElementToByteArray(point.getX(), point.getY());
	}

	@Override
	public GroupElement exponentiateWithPreComputedValues(GroupElement groupElement, BigInteger exponent) {
		//If the GroupElement doesn't match the DlogGroup, throw exception.
		if (!(groupElement instanceof ECFpPointOpenSSL)){
			throw new IllegalArgumentException("the given base doesn't match the DlogGroup");
		}
		
		if (!groupElement.equals(generator)){
			return exponentiate(groupElement, exponent);
		}

		//If the exponent is negative, convert it to be the exponent modulus q.
		if (exponent.compareTo(BigInteger.ZERO) < 0){
			exponent = exponent.mod(getOrder());
		}
				
		// Call the native exponentiate function.
		long result = exponentiateWithPreComputedValues(curve, exponent.toByteArray());
		// Build a ECFpPointOpenSSL element from the result.
		return new ECFpPointOpenSSL(curve, result);
	}
}