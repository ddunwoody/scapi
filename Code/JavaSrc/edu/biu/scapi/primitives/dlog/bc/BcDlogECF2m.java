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
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECFieldElement.F2m;

import edu.biu.scapi.primitives.dlog.DlogECF2m;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.ECF2mUtility;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mKoblitz;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mPentanomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mTrinomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;
import edu.biu.scapi.securityLevel.DDH;

/**
 * This class implements an Elliptic curve Dlog group over F2m utilizing Bouncy Castle's implementation. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class BcDlogECF2m extends BcAdapterDlogEC implements DlogECF2m, DDH{

	private ECF2mUtility util;
	
	/**
	 * Default constructor. Initializes this object with B-163 NIST curve.
	 */
	public BcDlogECF2m() throws IOException{
		this("B-163");
	}
	
	public BcDlogECF2m(String fileName, String curveName) throws IOException{
		super(fileName, curveName);
	}
	
	public BcDlogECF2m(String fileName, String curveName, String randNumGenAlg) throws IOException, NoSuchAlgorithmException{
		super(fileName, curveName, SecureRandom.getInstance(randNumGenAlg));
	}
	
	/**
	 * Constructor that initialize this DlogGroup with one of NIST recommended elliptic curve
	 * @param curveName - name of NIST curve to initialized
	 * @throws IOException 
	 * @throws IllegalAccessException
	 */
	public BcDlogECF2m(String curveName) throws IllegalArgumentException, IOException{
		this(NISTEC_PROPERTIES_FILE, curveName);
	}
	
	public BcDlogECF2m(String curveName, SecureRandom random) throws IOException{
		super(NISTEC_PROPERTIES_FILE, curveName, random);
	}
	
	
	/*
	 * Extracts the parameters of the curve from the properties object and initialize the groupParams, 
	 * generator and the underlying curve. 
	 * @param ecProperties - properties object contains the curve file data
	 * @param curveName - the curve name as it is called in the file
	 */
	protected void doInit(Properties ecProperties, String curveName) {
		//Delegate the work on the params to the ECF2mUtility since this work does not depend on BC library. 
		util = new ECF2mUtility();
		groupParams = util.checkAndCreateInitParams(ecProperties, curveName);
		//Create a BC underlying curve:
		createUnderlyingCurveAndGenerator();
	}
	
	private void createUnderlyingCurveAndGenerator(){
		BigInteger x;
		BigInteger y;
		GroupParams params = groupParams;
		if (groupParams instanceof ECF2mKoblitz){
			params = ((ECF2mKoblitz) groupParams).getCurve();
		}
		if(params instanceof ECF2mTrinomialBasis){
			ECF2mTrinomialBasis triParams = (ECF2mTrinomialBasis)params;		
			curve = new ECCurve.F2m(triParams.getM(), triParams.getK1(), triParams.getA(), triParams.getB(), triParams.getQ(), triParams.getCofactor());
			x = triParams.getXg();
			y = triParams.getYg();
		}else{
			//we assume that if it's not trinomial then it's pentanomial. We do not check.
			ECF2mPentanomialBasis pentaParams = (ECF2mPentanomialBasis) params;
			curve = new ECCurve.F2m(pentaParams.getM(), pentaParams.getK1(), pentaParams.getK2(), pentaParams.getK3(),  pentaParams.getA(), pentaParams.getB(), pentaParams.getQ(), pentaParams.getCofactor());		
			x = pentaParams.getXg();
			y = pentaParams.getYg();
		}
		
		//Create the generator
		//Assume that (x,y) are the coordinates of a point that is indeed a generator but check that (x,y) are the coordinates of a point.
		generator = new ECF2mPointBc(x, y, this, true);
	}
	
	/**
	 * 
	 * @return the type of the group - ECF2m
	 */
	public String getGroupType(){
		return util.getGroupType();
	}
	
	/**
	 * Checks if the given element is a member of this Dlog group
	 * @param element 
	 * @return true if the given element is member of this group; false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) throws IllegalArgumentException{
		
		if (!(element instanceof ECF2mPointBc)){
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		
		ECF2mPointBc point = (ECF2mPointBc) element;
		
		//infinity point is a valid member
		if (point.isInfinity()){
			return true;
		}
		
		// A point (x, y) is a member of a Dlog group with prime order q over an Elliptic Curve if it meets the following two conditions:
		// 1)	P = (x,y) is a point in the Elliptic curve, i.e (x,y) is a solution of the curve’s equation.
		// 2)	P = (x,y) is a point in the q-order group which is a sub-group of the Elliptic Curve.
		// those two checks is done in two steps:
		// 1.	Checking that the point is on the curve, performed by checkCurveMembership
		// 2.	Checking that the point is in the Dlog group,performed by checkSubGroupMembership

		boolean valid = checkCurveMembership((ECF2mGroupParams) groupParams, point.getX(), point.getY());
		valid = valid && util.checkSubGroupMembership(this, point);
		
		return valid;
			
	}
	
	/**
	 * Checks if the given x and y represent a valid point on the given curve, 
	 * i.e. if the point (x, y) is a solution of the curve’s equation.
	 * @param params elliptic curve over F2m parameters
	 * @param x coefficient of the point
	 * @param y coefficient of the point
	 * @return true if the given x and y represented a valid point on the given curve
	 */
	boolean checkCurveMembership(ECF2mGroupParams params, BigInteger x, BigInteger y){
		
		int m = params.getM(); // get the field size
		
		// get curve basis
		int[] k = new int[3];
		
		if (params instanceof ECF2mKoblitz) {
			getBasis(((ECF2mKoblitz) params).getCurve(), k);
		} else
			getBasis(params, k);
		
		// construct ECFieldElements from a,b,x,y. 
		// Elements in the binary field are polynomials so we can't treat them as regular BigInteger. 
		// We use BC library to create and deal with such field element.
		ECFieldElement.F2m xElement = new ECFieldElement.F2m(m, k[0], k[1], k[2], x);
		ECFieldElement.F2m yElement = new ECFieldElement.F2m(m, k[0], k[1], k[2], y);
		ECFieldElement.F2m a = new ECFieldElement.F2m(m, k[0], k[1], k[2], params.getA());
		ECFieldElement.F2m b = new ECFieldElement.F2m(m, k[0], k[1], k[2], params.getB());
		
		
		// Calculates the curve equation with the given x,y.
		
		// compute x^3
		ECFieldElement.F2m xPow2 = (F2m) xElement.square();
		ECFieldElement.F2m xPow3 = (F2m) xPow2.multiply(xElement);
		// compute ax^2
		ECFieldElement.F2m axPow2 = (F2m) a.multiply(xPow2);
		// compute x^3+ax^2+b
		ECFieldElement.F2m addition = (F2m) xPow3.add(axPow2);
		ECFieldElement.F2m rightSide = (F2m) addition.add(b);
		
		// compute xy
		ECFieldElement.F2m xy = (F2m) yElement.multiply(xElement);
		// compute y^2+xy
		ECFieldElement.F2m yPow2 = (F2m) yElement.square();
		ECFieldElement.F2m leftSide = (F2m) yPow2.add(xy);
		
		//if the the equation is solved - the point is in the elliptic curve and return true
		if (leftSide.equals(rightSide))
			return true;
		else return false;
	}
	
	/**
	 * Returns the reduction polnomial F(z)
	 * @param params curve parameters.
	 * @param k array that holds the reduction polynomial.
	 */
	private void getBasis(GroupParams params, int[] k) {
		
		if (params instanceof ECF2mTrinomialBasis) {
			k[0] = ((ECF2mTrinomialBasis) params).getK1();
		}
		if (params instanceof ECF2mPentanomialBasis) {
			k[0] = ((ECF2mPentanomialBasis) params).getK1();
			k[1] = ((ECF2mPentanomialBasis) params).getK2();
			k[2] = ((ECF2mPentanomialBasis) params).getK3();
		}
	}
	
	/**
	 * @deprecated As of SCAPI-V2_0_0 use generateElment(boolean bCheckMembership, BigInteger...values)
	 */
	@Deprecated public ECElement generateElement(BigInteger x, BigInteger y) throws IllegalArgumentException{
		//Creates element with the given values.
		ECF2mPointBc point =  new ECF2mPointBc(x, y, this,true);
		
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
		ECF2mPointBc point =  new ECF2mPointBc(values[0], values[1], this, bCheckMembership);

		if(bCheckMembership){
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
	 * Creates ECPoint.F2m with the given parameters
	 */
	protected GroupElement createPoint(ECPoint result) {
		return new ECF2mPointBc(result);
	}
	
	/**
	 * Check if the element is valid to this elliptic curve group
	 */
	protected boolean checkInstance(GroupElement element){
		if (element instanceof ECF2mPointBc){
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * Creates ECPoint.F2m with infinity values
	 */
	public ECElement getInfinity(){
		ECPoint infinity = curve.getInfinity();
		return new ECF2mPointBc(infinity);
	}
	
	/**
	 * Encode a byte array to an ECF2mPointBc. Some constraints on the byte array are necessary so that it maps into an element of this group.
	 * <B>Currently we don't support this conversion.</B> It will be implemented in the future.Meanwhile we return null.
	 * @param binaryString the byte array to convert
	 * @return null
	 */
	public GroupElement encodeByteArrayToGroupElement(byte[] binaryString){
		//currently we don't support this conversion. 
		//will be implemented in the future.
		return null;
	}
	
	/**
	 * Decode an ECF2mPointBc that was obtained through the encodeByteArrayToGroupElement function to the original byte array.
	 * <B>Currently we don't support this conversion.</B> It will be implemented in the future.Meanwhile we return null.
	 * @param groupElement the element to convert
	 * @return the created byte array
	 */
	public byte[] decodeGroupElementToByteArray(GroupElement groupElement){
		if (!(groupElement instanceof ECF2mPointBc)){
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		//currently we don't support this conversion. 
		//will be implemented in the future.
		return null;
	}

	/**
	 * This function returns the value k which is the maximum length of a string to be converted to a Group Element of this group.<p>
	 * If a string exceeds the k length it cannot be converted
	 * <B>Currently we do not have a proper algorithm for this therefore we return 0.</B>
	 * 
	 * @return k the maximum length of a string to be converted to a Group Element of this group
	 */
	public int getMaxLengthOfByteArrayForEncoding() {
		//Currently we do not have a proper algorithm for this.
		//Return 0
		return 0;
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
		if (!(groupElement instanceof ECF2mPointBc)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		ECF2mPointBc point = (ECF2mPointBc) groupElement;
		//The actual work is implemented in ECF2mUtility since it is independent of the underlying library (BC, Miracl, or other)
		//If we ever decide to change the implementation there will only one place to change it.
		return util.mapAnyGroupElementToByteArray(point.getX(), point.getY());
	}

}
