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


package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;
import java.util.Properties;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mKoblitz;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mPentanomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mTrinomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

/**
 * This class is a utility class for elliptic curve classes over F2m field.
 * It operates some functionality that is common for every elliptic curve over F2m.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECF2mUtility {

	//Default constructor.
	public ECF2mUtility() {
		super();
	}
	
	/**
	 * checks if the given point is in the given dlog group with the q prime order. 
	 * A point is in the group if it in the q-order group which is a sub-group of the Elliptic Curve.
	 * The basic assumption of this function is that checkCurveMembership function has already been called and returned true.
	 * @param curve
	 * @param point
	 * @return true if the given point is in the given dlog group.
	 */
	public boolean checkSubGroupMembership(DlogECF2m curve, ECF2mPoint point){
		//we assume that the point is on the curve group
		//get the cofactor of the group
		ECF2mGroupParams params = (ECF2mGroupParams) curve.getGroupParams();
		BigInteger h = params.getCofactor();
		
		//if the cofactor is 1 the sub-group is same as the elliptic curve equation which the point is in.
		if (h.equals(BigInteger.ONE)){
			return true;
		}
		
		BigInteger x = point.getX();
		
		//if the cofactor is greater than 1, the point must have order q (same as the order of the group)
		
		//if the cofactor is 2 and the x coefficient is 0, the point has order 2 and is not in the group
		if (h.equals(new BigInteger("2"))){
			if (x.equals(BigInteger.ZERO)){
				return false;
			} else {
				return true;
			}
		}
		
		// if the cofactor is 3 and p^2 = p^(-1), the point has order 3 and is not in the group
		if (h.equals(new BigInteger("3"))){
			GroupElement power = curve.exponentiate(point, new BigInteger("2"));
			GroupElement inverse = curve.getInverse(point);
			if (power.equals(inverse)){
				return false;
			} else {
				return true;
			}
		}
		
		// if the cofactor is 4, the point has order 2 if the x coefficient of the point is 0, 
		// or the the point has order 4 if the x coefficient of the point raised to two is 0.
		// in both cases the point is not in the group.
		if (h.equals(new BigInteger("4"))){
			if (x.equals(BigInteger.ZERO)){
				return false;
			}
			GroupElement power = curve.exponentiate(point, new BigInteger("2"));
			BigInteger powerX = ((ECElement) power).getX();
			if (powerX.equals(BigInteger.ZERO)){
				return false;
			} else {
				return true;
			}
		}
		
		// if the cofactor is bigger than 4, there is no optimized way to check the order, so we operates the naive:
		// if the point raised to q (order of the group) is the identity, the point has order q too and is in the group. 
		// else, it is not in the group
		BigInteger r = params.getQ();
		GroupElement pointPowR = curve.exponentiate(point, r);
		if (pointPowR.isIdentity()){
			return true;
		} else {
			return false;
		}
	}
	
	
	public GroupParams checkAndCreateInitParams(Properties ecProperties, String curveName) {
		// check that the given curve is in the field that matches the group
		if (!curveName.startsWith("B-") && !curveName.startsWith("K-")) {
			throw new IllegalArgumentException("curveName is not a curve over F2m field and doesn't match the DlogGroup type"); 
		}

		// get the curve parameters:
		// The degree of the field.
		int m = Integer.parseInt(ecProperties.getProperty(curveName));
		//If an irreducible trinomial t^m + t^k + 1 exists over GF(2), then the field polynomial p(t) is chosen to be the irreducible 
		//trinomial with the lowest degree middle term t^k. 
		//If no irreducible trinomial exists, then one selects instead a pentanomial t^m+t^k+t^k2+t^k3+1. The particular pentanomial 
		//chosen has the following properties: the second term t^k has the lowest degree among all irreducible pentanomials of degree m; 
		//the third term t^k2 has the lowest degree among all irreducible pentanomials of degree m and second term t^k; 
		//and the fourth term t^k3 has the lowest degree among all irreducible pentanomials of degree m, second term t^k, and third term t^k2.
		int k = Integer.parseInt(ecProperties.getProperty(curveName + "k"));
		String k2Property = ecProperties.getProperty(curveName + "k2"); //we hold that as a string an not as int because is can be null.
		String k3Property = ecProperties.getProperty(curveName + "k3");
		
		//Coefficients of the curve equaltion.
		BigInteger a = new BigInteger(ecProperties.getProperty(curveName + "a"));
		BigInteger b = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"b")));
		
		//Coordinates x, y, of the base point (generator).
		BigInteger x = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"x")));
		BigInteger y = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"y")));
		
		//The order of the group.
		BigInteger q = new BigInteger(ecProperties.getProperty(curveName + "r"));
		
		//the cofactor of the curve.
		BigInteger h = new BigInteger(ecProperties.getProperty(curveName + "h"));
		
		int k2 = 0;
		int k3 = 0;
		
		GroupParams groupParams = null;
		// for trinomial basis, where there is just one value represents the irreducible polynomial.
		if (k2Property == null && k3Property == null) { 
			groupParams = new ECF2mTrinomialBasis(q, x, y, m, k, a, b, h);
			
		} else if (k2Property != null && k3Property != null){ // pentanomial basis must have three k values.
			k2 = Integer.parseInt(k2Property);
			k3 = Integer.parseInt(k3Property);
			groupParams = new ECF2mPentanomialBasis(q, x, y, m, k, k2, k3, a, b, h);
		} else { //if the irreducible polynomial is not trinomial or pentanomial.
			throw new IllegalArgumentException("the given irreducible polynomial is not trinomial or pentanomial basis");
		}
		// koblitz curve
		if (curveName.contains("K-")) {

			groupParams = new ECF2mKoblitz((ECF2mGroupParams) groupParams, q, h);
		}

		return groupParams;
	}
	
	/**
	 * @return the type of the group - ECF2m
	 */
	public String getGroupType(){
		return "ECF2m";
	}
	
	/**
	 * This function maps any group element to a byte array. This function does not have an inverse,<p>
	 * that is, it is not possible to re-construct the original group element from the resulting byte array.
	 * @param x coordinate of a point in the curve (this function does not check for membership)
	 * @param y coordinate of a point in the curve (this function does not check for membership)
	 * @return byte[] representation
	 */
	public byte[] mapAnyGroupElementToByteArray(BigInteger x, BigInteger y) {
		//This function simply returns an array which is the result of concatenating 
		//the byte array representation of x with the byte array representation of y.
		byte[] xByteArray = x.toByteArray();
		byte[] yByteArray = y.toByteArray();

		byte[] result = new byte[xByteArray.length + yByteArray.length];
		System.arraycopy(xByteArray, 0, result, 0, xByteArray.length);
		System.arraycopy(yByteArray, 0, result, xByteArray.length, yByteArray.length);
		return result;
	}
	
}
