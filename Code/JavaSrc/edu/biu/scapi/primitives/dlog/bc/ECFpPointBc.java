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

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

import edu.biu.scapi.primitives.dlog.ECFpPoint;
import edu.biu.scapi.primitives.dlog.ECFpUtility;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;

/**
 * This class is an adapter for ECPoint.Fp of BC
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 * 
 */
public class ECFpPointBc extends ECPointBc implements ECFpPoint{

	private ECFpUtility util = new ECFpUtility();
	
	/**
	 * Constructor that accepts x,y possible values of a point on the requested curve.
	 * If bCheckMembership is set to true it checks if the values are valid and if so, sets the point. If not valid, throws IllegalArgumentException
	 * If bCheckMembership is set to false it creates the point without checking.
	 * @param x coordinate of candidate point
	 * @param y coordinate of candidate point
	 * @param curve - DlogGroup for which we want to create the point
	 * @param bCheckMembership whether to check if (x,y) are a valid point on curve or not 
	 * @throws IllegalArgumentException if bCheckMembership is set to true AND if the coordinates x and y do not represent a valid point in the curve
	 */
	ECFpPointBc(BigInteger x, BigInteger y, BcDlogECFp curve, boolean bCheckMembership) throws IllegalArgumentException{
		if(bCheckMembership){
			//checks if the given parameters are valid point on the curve.
			boolean valid = util.checkCurveMembership((ECFpGroupParams) curve.getGroupParams(), x, y);
			// checks validity
			if (valid == false) // if not valid, throws exception
				throw new IllegalArgumentException("x, y values are not a point on this curve");
		}
		/* create point with the given parameters */
		point = curve.createPoint(x, y);
	}

	/*
	 * Constructor that gets an element and sets it. 
	 * Only our inner functions use this constructor to set an element. 
	 * The ECPoint is a result of our DlogGroup functions, such as multiply.
	 * 	 * @param point
	 */
	ECFpPointBc(ECPoint point) {
		this.point = point;
	}

}
