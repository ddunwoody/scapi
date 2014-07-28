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

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Properties;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import edu.biu.scapi.primitives.dlog.DlogECFp;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.ECFpUtility;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;
import edu.biu.scapi.securityLevel.DDH;


/**
 * This class implements an Elliptic curve Dlog group over Fp utilizing Bouncy Castle's implementation. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class BcDlogECFp extends BcAdapterDlogEC implements DlogECFp, DDH {
	
	private ECFpUtility util;
	
	
	/**
	 * Default constructor. Initializes this object with P-192 NIST curve.
	 */
	public BcDlogECFp() throws IOException{
		this("P-192");
	}
	
	public BcDlogECFp(String fileName, String curveName) throws IOException {
		super(fileName, curveName);
	}
	
	public BcDlogECFp(String fileName, String curveName, String randNumGenAlg) throws IOException, NoSuchAlgorithmException {
		super(fileName, curveName, SecureRandom.getInstance(randNumGenAlg));
	}
	
	/**
	 * Initialize this DlogGroup with one of NIST recommended elliptic curve
	 * @param curveName - name of NIST curve to initialized
	 * @throws IOException 
	 */
	public BcDlogECFp(String curveName) throws IllegalArgumentException, IOException {
		this(NISTEC_PROPERTIES_FILE, curveName);
	}
	
	/**
	 * Initialize this DlogGroup with one of NIST recommended elliptic curve
	 * @param curveName - name of NIST curve to initialized
	 * @param random The source of randomness to use.
	 * @throws IOException 
	 */
	public BcDlogECFp(String curveName, SecureRandom random) throws IOException {
		super(NISTEC_PROPERTIES_FILE, curveName, random);
	}

	/**
	 * Extracts the parameters of the curve from the properties object and initialize the groupParams, 
	 * generator and the underlying curve
	 * @param ecProperties properties object contains the curve file data
	 * @param curveName the curve name as it is called in the file
	 */
	protected void doInit(Properties ecProperties, String curveName) {
		util = new ECFpUtility();
		groupParams = util.checkAndCreateInitParams(ecProperties, curveName);
		//Now that we have p, we can calculate k which is the maximum length in bytes of a string to be converted to a Group Element of this group. 
		BigInteger p = ((ECFpGroupParams)groupParams).getP();
		k = util.calcK(p);
		createUnderlyingCurveAndGenerator(groupParams);
	}
	

	/**
	 * Extracts the parameters of the curve from the groupParams, and create the corresponding BC curve and generator. 
	 * generator and the underlying curve
	 * @param params of type ECFpGroupParams
	 */
	private void createUnderlyingCurveAndGenerator(GroupParams params){
		//There is no need to check that the params passed are an instance of ECFpGroupParams since this function is only used by SCAPI.
		ECFpGroupParams fpParams = (ECFpGroupParams)params;
		// create the ECCurve
		curve = new ECCurve.Fp(fpParams.getP(), fpParams.getA(), fpParams.getB());

		//Create the generator
		//Assume that (x,y) are the coordinates of a point that is indeed a generator but check that (x,y) are the coordinates of a point.
		generator = new ECFpPointBc(fpParams.getXg(), fpParams.getYg(), this, true);
	}
	
	
	/**
	 * @return the type of the group - ECFp
	 */
	public String getGroupType() {
		return util.getGroupType();
	}
	
	/**
	 * Checks if the given element is a member of this Dlog group
	 * @param element 
	 * @return true if the given element is member of this group; false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) throws IllegalArgumentException{
		
		if (!(element instanceof ECFpPointBc)){
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		
		ECFpPointBc point = (ECFpPointBc) element;
		
		//infinity point is a valid member
		if (point.isInfinity()){
			return true;
		}
		
		// A point (x, y) is a member of a Dlog group with prime order q over an Elliptic Curve if it meets the following two conditions:
		// 1)	P = (x,y) is a point in the Elliptic curve, i.e (x,y) is a solution of the curve’s equation.
		// 2)	P = (x,y) is a point in the q-order group which is a sub-group of the Elliptic Curve.
		// those two checks are done in two steps:
		// 1.	Checking that the point is on the curve, performed by checkCurveMembership
		// 2.	Checking that the point is in the Dlog group,performed by checkSubGroupMembership

		boolean valid = util.checkCurveMembership((ECFpGroupParams) groupParams, point.getX(), point.getY());
		valid = valid && util.checkSubGroupMembership(this, point);
		
		return valid;
			
	}
	
	/**
	 * @deprecated As of SCAPI-V2_0_0 use generateElment(boolean bCheckMembership, BigInteger...values)
	 */
	@Deprecated public ECElement generateElement(BigInteger x, BigInteger y) throws IllegalArgumentException{
		//Creates element with the given values.
		ECFpPointBc point =  new ECFpPointBc(x, y, this, true);
		
		//if the element was created, it is a point on the curve.
		//checks if the point is in the sub-group, too.
		boolean valid = util.checkSubGroupMembership(this, point);
		
		//if the point is not in the sub-group, throw exception.
		if (valid == false){
			throw new IllegalArgumentException("Could not generate the element. The given (x, y) is not a point in this Dlog group");
		}
		
		return point;
	}
	
	
	
	/* (non-Javadoc)
	 * @see edu.biu.scapi.primitives.dlog.DlogGroup#generateElement(boolean, java.math.BigInteger[])
	 */
	@Override
	public GroupElement generateElement(boolean bCheckMembership, BigInteger... values) throws IllegalArgumentException {
		if(values.length != 2){
			throw new IllegalArgumentException("To generate an ECElement you should pass the x and y coordinates of the point");
		}
		//Creates element with the given values.
		ECFpPointBc point =  new ECFpPointBc(values[0], values[1], this, bCheckMembership);
		
		if(bCheckMembership) {
			//if the element was created, it is a point on the curve.
			//checks if the point is in the sub-group, too.
			boolean valid = util.checkSubGroupMembership(this, point);
			
			//if the point is not in the sub-group, throw exception.
			if (valid == false){
				throw new IllegalArgumentException("Could not generate the element. The given (x, y) is not a point in this Dlog group");
			}
		}
		return point;
	}
	
	
	/**
	 * Creates ECPoint.Fp with the given parameters
	 */
	protected GroupElement createPoint(ECPoint result) {
		return new ECFpPointBc(result);
	}
	
	/**
	 * Check if the element is valid to this elliptic curve group
	 */
	protected boolean checkInstance(GroupElement element) {
		if (element instanceof ECFpPointBc) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Creates ECPoint.Fp with infinity values
	 */
	public ECElement getInfinity() {
		ECPoint infinity = curve.getInfinity();
		return new ECFpPointBc(infinity);
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
		ECFpUtility.FpPoint fpPoint = util.findPointRepresentedByByteArray((ECFpGroupParams) groupParams, binaryString, k); 
		if (fpPoint == null)
			return null;
		//When generating an element for an encoding always check that the (x,y) coordinates represent a point on the curve.
		ECElement element = (ECElement) generateElement(true, fpPoint.getX(), fpPoint.getY());
		return element;
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
		if (!(groupElement instanceof ECFpPointBc)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		ECFpPointBc point = (ECFpPointBc) groupElement;
		byte[] xByteArray = point.getX().toByteArray();
		byte bOriginalSize = xByteArray[xByteArray.length -1];
		
		byte[] b2 = new byte[bOriginalSize];
		System.arraycopy(xByteArray,xByteArray.length -1  -  bOriginalSize, b2, 0, bOriginalSize);
		return b2;
	}

	/**
	 * This function maps a group element of this dlog group to a byte array.<p>
	 * This function does not have an inverse function, that is, it is not possible to re-construct the original group element from the resulting byte array.<p>
	 * Moreover, the implementation of this function is such that for a given group element (point in the curve),<p>
	 * the result of applying this function (mapAnyGroupElementToByteArray) and the result of applying decodeGroupElementToByteArray are not equal.    
	 * @return a byte array representation of the given group element
	 */
	public byte[] mapAnyGroupElementToByteArray(GroupElement groupElement) {
		//This function simply returns an array which is the result of concatenating 
		//the byte array representation of x with the byte array representation of y.
		if (!(groupElement instanceof ECFpPointBc)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		ECFpPointBc point = (ECFpPointBc) groupElement;
		//The actual work is implemented in ECFpUtility since it is independent of the underlying library (BC, Miracl, or other)
		//If we ever decide to change the implementation there will only one place to change it.
		return util.mapAnyGroupElementToByteArray(point.getX(), point.getY());
	}

}
