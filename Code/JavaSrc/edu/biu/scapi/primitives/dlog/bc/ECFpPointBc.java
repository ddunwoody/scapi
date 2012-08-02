/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
package edu.biu.scapi.primitives.dlog.bc;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECFieldElement.Fp;

import edu.biu.scapi.primitives.dlog.ECFpPoint;
import edu.biu.scapi.primitives.dlog.ECFpUtility;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ECGroupParams;

/**
 * This class is an adapter for ECPoint.Fp of BC
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 * 
 */
public class ECFpPointBc extends ECPointBc implements ECFpPoint{

	private ECFpUtility util = new ECFpUtility();
	
	/**
	 * Constructor that accepts x,y values of a point. 
	 * if the values are valid - set the point.
	 * 
	 * @param x
	 * @param y
	 * @param curve DlogGroup
	 */
	ECFpPointBc(BigInteger x, BigInteger y, BcDlogECFp curve) throws IllegalArgumentException{
		//checks if the given parameters are valid point on the curve.
		boolean valid = util.checkCurveMembership((ECFpGroupParams) curve.getGroupParams(), x, y);
		// checks validity
		if (valid == false) // if not valid, throws exception
			throw new IllegalArgumentException("x, y values are not a point on this curve");

		/* create point with the given parameters */
		point = curve.createPoint(x, y);
	}

	/**
	 * Constructor that accepts x value of a point, calculates its corresponding
	 * y value and create a point with these values.
	 * @param x the x coordinate of the point
	 * @param curve elliptic curve dlog group over Fp
	 */
	ECFpPointBc(BigInteger x, BcDlogECFp curve) {
		// This constructor is NOT guarantee that the created point is in the group. 
		// It creates a point on the curve, but this point is not necessarily a point in the dlog group, 
		// which is a sub-group of the elliptic curve.

		BigInteger p = ((ECFpGroupParams) curve.getGroupParams()).getP();
		ECFieldElement.Fp xElement = new ECFieldElement.Fp(p, x);
		ECFieldElement.Fp aElement = new ECFieldElement.Fp(p, ((ECGroupParams) curve.getGroupParams()).getA());
		ECFieldElement.Fp bElement = new ECFieldElement.Fp(p, ((ECGroupParams) curve.getGroupParams()).getB());
		// computes x^3
		ECFieldElement.Fp x3 = (Fp) xElement.square().multiply(xElement);
		// computes x^3+ax+b
		ECFieldElement.Fp result = (Fp) x3.add(aElement.multiply(xElement)).add(bElement);
		// computes sqrt(x^3+ax+b)
		ECFieldElement.Fp yVal = (Fp) result.sqrt();
		if (yVal != null) { // if there is a square root, creates a point
			BigInteger y = yVal.toBigInteger();
			// creates the point
			point = ((BcAdapterDlogEC) curve).createPoint(x, y);
		} else {
			throw new IllegalArgumentException("the given x has no corresponding y in the current curve");
		}
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
