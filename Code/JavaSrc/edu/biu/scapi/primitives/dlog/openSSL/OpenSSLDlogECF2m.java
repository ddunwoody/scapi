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

import edu.biu.scapi.primitives.dlog.DlogECF2m;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.ECF2mUtility;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mKoblitz;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mPentanomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mTrinomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.ECGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;
import edu.biu.scapi.securityLevel.DDH;

/**
 * This class implements an Elliptic curve Dlog group over F2m utilizing OpenSSL's implementation. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OpenSSLDlogECF2m extends OpenSSLAdapterDlogEC implements DlogECF2m, DDH{
	
	private ECF2mUtility util; //Utility class that computes some common ECF2m functionalities.
	
	//Creates the native curve.
	private native long createCurve(byte[] p, byte[] a, byte[] b);
	//Initializes the native curve with the generator and order.
	private native int initCurve(long curve, long generator, byte[] q, byte[] cofactor);
	
	/**
	 * Default constructor. Initializes this object with K-163 NIST curve.
	 */
	public OpenSSLDlogECF2m() throws IOException {
		this("K-163");
	}
	
	/**
	 * Initializes this DlogGroup with the curve in the given file.
	 * @param fileName the file to take the curve's parameters from.
	 * @param curveName name of curve to initialized.
	 * @throws IOException if there is a problem with the given file name.
	 */
	public OpenSSLDlogECF2m(String fileName, String curveName) throws IOException {
		super(fileName, curveName);	
	}
	
	/**
	 * Initializes this DlogGroup with the curve in the given file.
	 * @param fileName the file to take the curve's parameters from.
	 * @param curveName name of curve to initialized.
	 * @param randNumGenAlg The random number generator to use.
	 * @throws IOException if there is a problem with the given file name.
	 * @throws NoSuchAlgorithmException 
	 */
	public OpenSSLDlogECF2m(String fileName, String curveName, String randNumGenAlg) throws IOException, NoSuchAlgorithmException {
		super(fileName, curveName, SecureRandom.getInstance(randNumGenAlg));	
	}
	
	/**
	 * Initialize this DlogGroup with one of NIST recommended elliptic curve.
	 * @param curveName name of NIST curve to initialized
	 * @throws IOException if there is a problem with NIST properties file.
	 */
	public OpenSSLDlogECF2m(String curveName) throws IOException {
		super(curveName);
	}
	
	/**
	 * Initialize this DlogGroup with one of NIST recommended elliptic curve.
	 * @param curveName name of NIST curve to initialized
	 * @param random The source of randomness to use.
	 * @throws IOException if there is a problem with NIST properties file.
	 */
	public OpenSSLDlogECF2m(String curveName, SecureRandom random) throws IOException {
		super(curveName, random);
	}
	
	@Override
	protected void doInit(Properties ecProperties, String curveName) {
		util = new ECF2mUtility();
		groupParams = util.checkAndCreateInitParams(ecProperties, curveName);
		
		//There is no need to check that the params passed are an instance of ECF2mGroupParams since this function is only used by SCAPI.
		GroupParams params = groupParams;
		if (groupParams instanceof ECF2mKoblitz){
			params = ((ECF2mKoblitz) groupParams).getCurve();
		}
		// Open SSL accepts p, a, b to create the curve. 
		// In this case p represents the irreducible polynomial - each bit represents a term in the polynomial x^m + x^k3 + x^k2 + x^k1 + 1.
		BigInteger p = BigInteger.ZERO;
		p = p.setBit(0);
		
		//In case of trinomial basis, set the bits in m and k1 indexes.
		if(params instanceof ECF2mTrinomialBasis){
			ECF2mTrinomialBasis triParams = (ECF2mTrinomialBasis)params;
			p = p.setBit(triParams.getM());
			p = p.setBit(triParams.getK1());
		}else{
			//we assume that if it's not trinomial then it's pentanomial. We do not check.
			//In case of trinomial basis, set the bits in m, k1, k2 and k3 indexes.
			ECF2mPentanomialBasis pentaParams = (ECF2mPentanomialBasis) params;
			p = p.setBit(pentaParams.getM());
			p = p.setBit(pentaParams.getK1());
			p = p.setBit(pentaParams.getK2());
			p = p.setBit(pentaParams.getK3());
		}
		
		//Create the native curve.
		curve = createCurve(p.toByteArray(), ((ECGroupParams) params).getA().toByteArray(), ((ECGroupParams) params).getB().toByteArray());
		
		//Create the generator.
		generator  = new ECF2mPointOpenSSL(((ECGroupParams) params).getXg(), ((ECGroupParams) params).getYg(), this, true);
		
		//Initialize the native curve with the generator, order and cofactor.
		initCurve(curve, ((ECF2mPointOpenSSL) generator).getPoint(), params.getQ().toByteArray(), ((ECF2mGroupParams) params).getCofactor().toByteArray());
	}

	@Override
	public ECElement getInfinity() {
		//Create an infinity point and return it.
		long infinity = createInfinityPoint(curve);
		return new ECF2mPointOpenSSL(curve, infinity);
	}

	/**
	 * @return the type of the group - ECF2m.
	 */
	public String getGroupType() {
		return util.getGroupType();
	}

	@Override
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException {
		//If the GroupElement doesn't match the DlogGroup, throw exception.
		if (!(groupElement instanceof ECF2mPointOpenSSL)){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}

		// The inverse of infinity point is infinity.
		if (((ECF2mPointOpenSSL) groupElement).isInfinity()) {
			return groupElement;
		}

		long point = ((ECF2mPointOpenSSL) groupElement).getPoint();
		// Call the native inverse function.
		long result = inversePoint(curve, point);
		// Build a ECF2mPointOpenSSL element from the result.
		return new ECF2mPointOpenSSL(curve, result);
	}

	@Override
	public GroupElement exponentiate(GroupElement base, BigInteger exponent)
			throws IllegalArgumentException {
		//If the GroupElement doesn't match the DlogGroup, throw exception.
		if (!(base instanceof ECF2mPointOpenSSL)){
			throw new IllegalArgumentException("the given base doesn't match the DlogGroup");
		}

		// The inverse of infinity point is infinity.
		if (((ECF2mPointOpenSSL) base).isInfinity()) {
			return base;
		}

		//If the exponent is negative, convert it to be the exponent modulus q.
		if (exponent.compareTo(BigInteger.ZERO) < 0){
			exponent = exponent.mod(getOrder());
		}
				
		long point = ((ECF2mPointOpenSSL) base).getPoint();
		// Call the native exponentiate function.
		long result = exponentiate(curve, point, exponent.toByteArray());
		// Build a ECF2mPointOpenSSL element from the result.
		return new ECF2mPointOpenSSL(curve, result);
	}

	@Override
	public GroupElement multiplyGroupElements(GroupElement groupElement1, GroupElement groupElement2) throws IllegalArgumentException {
		// If the GroupElements don't match the DlogGroup, throw exception.
		if (!(groupElement1 instanceof ECF2mPointOpenSSL)) {
			throw new IllegalArgumentException("the first group element doesn't match the DlogGroup");
		}
		if (!(groupElement2 instanceof ECF2mPointOpenSSL)){
			throw new IllegalArgumentException("the second group element doesn't match the DlogGroup");
		}

		//If one of the points is the infinity point, the second one is the multiplication result.
		if (((ECF2mPointOpenSSL) groupElement1).isInfinity()) {
			return groupElement2;
		}
		if (((ECF2mPointOpenSSL) groupElement2).isInfinity()) {
			return groupElement1;
		}

		long point1 = ((ECF2mPointOpenSSL) groupElement1).getPoint();
		long point2 = ((ECF2mPointOpenSSL) groupElement2).getPoint();

		// Call the native multiply function.
		long result = multiply(curve, point1, point2);
		// Build a ECF2mPointOpenSSL element from the result.
		return new ECF2mPointOpenSSL(curve, result);

	}

	@Override
	public boolean isMember(GroupElement element) throws IllegalArgumentException {
		// Checks that the element is the correct object.
		if (!(element instanceof ECF2mPointOpenSSL)) {
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}

		ECF2mPointOpenSSL point = (ECF2mPointOpenSSL) element;
		// infinity point is a valid member.
		if (point.isInfinity()) {
			return true;
		}

		// A point (x, y) is a member of a Dlog group with prime order q over an Elliptic Curve if it meets the following two conditions:
		// 1)	P = (x,y) is a point in the Elliptic curve, i.e (x,y) is a solution of the curve’s equation.
		// 2)	P = (x,y) is a point in the q-order group which is a sub-group of the Elliptic Curve.
		// those two checks are done in two steps:
		// 1.	Checking that the point is on the curve, performed by checkCurveMembership.
		// 2.	Checking that the point is in the Dlog group,performed by checkSubGroupMembership.

		//The first check is done by the native library.
		boolean valid = checkCurveMembership(curve, point.getPoint());
		//The actual work is implemented in ECF2mUtility since it is independent of the underlying library (BC, Miracl, or other)
		//If we ever decide to change the implementation there will only be one place to change it.
		valid = valid && util.checkSubGroupMembership(this, point);
		
		return valid;
	}
	
	@Override
	public GroupElement generateElement(boolean bCheckMembership, BigInteger... values) throws IllegalArgumentException {
		if(values.length != 2){
			throw new IllegalArgumentException("To generate an ECElement you should pass the x and y coordinates of the point");
		}
		return new ECF2mPointOpenSSL(values[0], values[1], this, bCheckMembership);
	}

	@Override
	public GroupElement simultaneousMultipleExponentiations(GroupElement[] groupElements, BigInteger[] exponentiations) {
		
		//Our tests showed that for ECF2m the naive algorithm is faster than the simultaneousMultipleExponentiations algorithm.
		return computeNaive(groupElements, exponentiations);
	}

	/**
	 * Encode a byte array to an ECF2mPointBc. Some constraints on the byte array are necessary so that it maps into an element of this group.
	 * <B>Currently we don't support this conversion.</B> It will be implemented in the future. Meanwhile we return null.
	 * @param binaryString the byte array to convert
	 * @return the created group Element
	 */
	public GroupElement encodeByteArrayToGroupElement(byte[] binaryString) {
		//Currently we don't support this conversion. 
		//Will be implemented in the future.
		return null;
	}

	/**
	 * Decode an ECF2mPointBc that was obtained through the encodeByteArrayToGroupElement function to the original byte array.
	 * <B>Currently we don't support this conversion.</B> It will be implemented in the future. Meanwhile we return null.
	 * @param groupElement the element to convert
	 * @return the created byte array
	 */
	public byte[] decodeGroupElementToByteArray(GroupElement groupElement) {
		if (!(groupElement instanceof ECF2mPointOpenSSL)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		//Currently we don't support this conversion. 
		//Will be implemented in the future.
		return null;
	}


	/**
	 * This function maps a group element of this dlog group to a byte array.<p>
	 * This function does not have an inverse function, that is, it is not possible to re-construct the original group element from the resulting byte array. 
	 * @param groupElement the element to convert
	 * @return the byte array representation
	 */
	public byte[] mapAnyGroupElementToByteArray(GroupElement groupElement) {
		//This function simply returns an array which is the result of concatenating 
		//the byte array representation of x with the byte array representation of y.
		if (!(groupElement instanceof ECF2mPointOpenSSL)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		ECF2mPointOpenSSL point = (ECF2mPointOpenSSL) groupElement;
		
		//The actual work is implemented in ECF2mUtility since it is independent of the underlying library (BC, Miracl, or other)
		//If we ever decide to change the implementation there will only be one place to change it.
		return util.mapAnyGroupElementToByteArray(point.getX(), point.getY());
	}

	@Override
	public GroupElement exponentiateWithPreComputedValues(GroupElement groupElement, BigInteger exponent) {
		//If the GroupElement doesn't match the DlogGroup, throw exception.
		if (!(groupElement instanceof ECF2mPointOpenSSL)){
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
		// Build a ECF2mPointOpenSSL element from the result.
		return new ECF2mPointOpenSSL(curve, result);
		
	}
}
