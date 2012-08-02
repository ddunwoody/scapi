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
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElement.F2m;
import org.bouncycastle.math.ec.ECPoint;

import edu.biu.scapi.primitives.dlog.ECF2mPoint;
import edu.biu.scapi.primitives.dlog.ECF2mUtility;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mKoblitz;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mPentanomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mTrinomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

/**
 * This class is an adapter for ECPoint.F2m of BC
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 * 
 */
public class ECF2mPointBc extends ECPointBc implements ECF2mPoint {
	private ECF2mUtility util = new ECF2mUtility();
	
	/**
	 * Constructor that accepts x,y values of a point. 
	 * if the values are valid - set the point.
	 * @param x
	 * @param y
	 * @param curve - DlogGroup
	 */
	ECF2mPointBc(BigInteger x, BigInteger y, BcDlogECF2m curve) throws IllegalArgumentException{

		boolean valid = util.checkCurveMembership((ECF2mGroupParams) curve.getGroupParams(), x, y);
		// checks validity
		if (valid == false) // if not valid, throws exception
			throw new IllegalArgumentException("x, y values are not a point on this curve");

		/* create point with the given parameters */
		point = curve.createPoint(x, y);
	}
	
	/**
	 * Constructor that accepts x value of a point, calculates its corresponding
	 * y value and create a point with these values.
	 * 
	 * @param x the x coordinate of the point
	 * @param curve - elliptic curve dlog group over F2m
	 */
	ECF2mPointBc(BigInteger x, BcDlogECF2m curve) {
		
		// This constructor is NOT guarantee that the created point is in the group. 
		// It creates a point on the curve, but this point is not necessarily a point in the dlog group, 
		// which is a sub-group of the elliptic curve.
		
		try {
			ECF2mGroupParams params = (ECF2mGroupParams) curve.getGroupParams();

			int m = params.getM(); // get the field size
			/* get curve parameters */
			int[] k = new int[3];
			
			if (params instanceof ECF2mKoblitz)
				getBasis(((ECF2mKoblitz) params).getCurve(), k);
			else
				getBasis(params, k);
			
			SecureRandom random = new SecureRandom();
			/* calculates y value corresponding to x value */
			ECFieldElement.F2m xElement = new ECFieldElement.F2m(m, k[0], k[1], k[2], x);
			ECFieldElement.F2m aElement = new ECFieldElement.F2m(m, k[0], k[1], k[2], params.getA());
			ECFieldElement.F2m bElement = new ECFieldElement.F2m(m, k[0], k[1], k[2], params.getB());
			// computes x^3
			ECFieldElement.F2m x3 = (F2m) xElement.square().multiply(xElement);
			// computes ax^2
			ECFieldElement.F2m ax2 = (F2m) aElement.multiply(xElement.square());
			// computes f(x) = x^3+ax^2+b
			ECFieldElement.F2m fx = (F2m) x3.add(ax2).add(bElement);
			// computes 4(x^3+ax^2+b)
			ECFieldElement.F2m fx4 = (F2m) fx.multiply(new ECFieldElement.F2m(m, k[0], k[1], k[2], new BigInteger("4")));
			//computes x^2-4f(x)
			ECFieldElement.F2m delta = (F2m) xElement.square().add(fx4.negate());
			ECFieldElement.F2m yVal = null;
			ECFieldElement.F2m two = new ECFieldElement.F2m(m, k[0], k[1], k[2], new BigInteger("2"));
			
			// if the delta is 0 - there is 1 solution to the equation
			if (delta.toBigInteger().compareTo(BigInteger.ZERO) == 0) {
				// compute y value = -x/2
				yVal = (F2m) xElement.negate().divide(two);
			}
			//if the delta is greater than 0 - there are 2 solutions to the equation and we choose one of them to be the y value
			if (delta.toBigInteger().compareTo(BigInteger.ZERO) > 0){  
				Boolean coin = random.nextBoolean();
				if (coin==true){
					//compute y value = (-x+sqrt(f(x)))/2
					yVal = (F2m) xElement.negate().add(fx4.sqrt()).divide(two);
				} else yVal = (F2m) xElement.negate().add(fx4.sqrt().negate()).divide(two);
			}
			
			if (yVal != null) { // if there is a square root, create a point
				BigInteger y = yVal.toBigInteger();
				// create the point
				point = ((BcAdapterDlogEC) curve).createPoint(x, y);
			} else {
				throw new IllegalArgumentException("the given x has no corresponding y in the current curve");
			}
		} catch (RuntimeException e) {
			if (e.getMessage().equals("Not implemented")) {
				throw new RuntimeException("Create an ECF2mPointBC element will be available as soon as BC implements the sqrt function in ECFieldElement.F2m");
			}
		}
	}
	
	/*
	 * Constructor that gets an element and sets it.
	 * Only our inner functions use this constructor to set an element. 
	 * The ECPoint is a result of our DlogGroup functions, such as multiply.
	 * @param point
	 */
	ECF2mPointBc(ECPoint point) {
		this.point = point;
	}
	
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

}
