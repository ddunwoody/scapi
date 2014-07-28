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
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import edu.biu.scapi.primitives.dlog.DlogEllipticCurve;
import edu.biu.scapi.primitives.dlog.DlogGroupEC;
import edu.biu.scapi.primitives.dlog.GroupElement;

/*
 * This class is the adapter to Bouncy Castle implementation of elliptic curves.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class BcAdapterDlogEC extends DlogGroupEC 
							 implements DlogEllipticCurve{

	protected ECCurve curve; // BC elliptic curve
	
	protected BcAdapterDlogEC(){}
	
	public BcAdapterDlogEC(String fileName, String curveName) throws IOException {
		this(fileName, curveName, new SecureRandom());
	}
	
	public BcAdapterDlogEC(String fileName, String curveName, SecureRandom random) throws IOException {
		super(fileName, curveName, random);
	}

	/*
	 * Creates an ECPoint from the given x,y
	 * @param x
	 * @param y
	 * @return ECPoint - the created point
	 */
	ECPoint createPoint(BigInteger x, BigInteger y){
		
		return curve.createPoint(x, y, false);
	}
	
	/*
	 * Calculates the inverse of the given GroupElement
	 * @param groupElement to inverse
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 */
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException{
		
		//if the GroupElement doesn't match the DlogGroup, throws exception
		if (!(checkInstance(groupElement))){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}
		
		//the inverse of infinity point is infinity
		if (((ECPointBc) groupElement).isInfinity()){
			return groupElement;
		}
		
		//gets the ECPoint
		ECPoint point1 = ((ECPointBc)groupElement).getPoint();
		
		/* 
		 * BC treats EC as additive group while we treat that as multiplicative group. 
		 * Therefore, invert point is negate.
		 */
		ECPoint result = point1.negate();
		
		//creates GroupElement from the result
		return createPoint(result);
		
	}

	/*
	 * Calculates the exponentiate of the given GroupElement
	 * @param exponent
	 * @param base 
	 * @return the result of the exponentiation
	 * @throws IllegalArgumentException
	 */
	public GroupElement exponentiate(GroupElement base, BigInteger exponent) 
									 throws IllegalArgumentException{
		
		//if the GroupElements don't match the DlogGroup, throws exception
		if (!(checkInstance(base))){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}
		
		//infinity remains the same after any exponentiate
		if (((ECPointBc) base).isInfinity()){
			return base;
		}
		
		//gets the ECPoint
		ECPoint point = ((ECPointBc)base).getPoint();
		
		//If the exponent is negative, convert it to be the exponent modulus q.
		if (exponent.compareTo(BigInteger.ZERO) < 0){
			exponent = exponent.mod(getOrder());
		}
		
		/* 
		 * BC treats EC as additive group while we treat that as multiplicative group. 
		 * Therefore, exponentiate point is multiply.
		 */
		ECPoint result = point.multiply(exponent);
		
		//creates GroupElement from the result
		return createPoint(result);
		
	}
	
	/*
	 * Multiplies two GroupElements
	 * @param groupElement1
	 * @param groupElement2
	 * @return the multiplication result
	 * @throws IllegalArgumentException
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1, 
						GroupElement groupElement2) throws IllegalArgumentException{
		
		//if the GroupElements don't match the DlogGroup, throws exception
		if (!(checkInstance(groupElement1))){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}
		if (!(checkInstance(groupElement2))){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}
			
		//if one of the points is the infinity point, the second one is the multiplication result
		if (((ECPointBc) groupElement1).isInfinity()){
			return groupElement2;
		}
		if (((ECPointBc) groupElement2).isInfinity()){
			return groupElement1;
		}
	
		//gets the ECPoints
		ECPoint point1 = ((ECPointBc)groupElement1).getPoint();
		ECPoint point2 = ((ECPointBc)groupElement2).getPoint();
		
		/* 
		 * BC treats EC as additive group while we treat that as multiplicative group. 
		 * Therefore, multiply point is add.
		 */
		ECPoint result = point1.add(point2);
		
		//creates GroupElement from the result
		return createPoint(result);
		
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
	public GroupElement simultaneousMultipleExponentiations
					(GroupElement[] groupElements, BigInteger[] exponentiations){
		for (int i=0; i < groupElements.length; i++){
			if (!checkInstance(groupElements[i])){
				throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
			}
		}
		//Our test results show that for BC elliptic curve the LL algorithm always gives the best performances
		return computeLL(groupElements, exponentiations);
	}
	
	/*
	 * Each of the concrete classes implements this function.
	 * BcDlogECFp creates an ECPoint.Fp
	 * BcDlogECF2m creates an ECPoint.F2m
	 */
	protected abstract GroupElement createPoint(ECPoint result);
	
	/**
	 * Checks if the element is valid to this elliptic curve group.
	 */
	protected abstract boolean checkInstance(GroupElement element);

}
