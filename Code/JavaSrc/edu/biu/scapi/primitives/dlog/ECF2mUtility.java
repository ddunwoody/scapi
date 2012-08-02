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
package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;
import java.util.Properties;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElement.F2m;
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
	 * Checks if the given x and y represent a valid point on the given curve, 
	 * i.e. if the point (x, y) is a solution of the curve’s equation.
	 * @param params elliptic curve over F2m parameters
	 * @param x coefficient of the point
	 * @param y coefficient of the point
	 * @return true if the given x and y represented a valid point on the given curve
	 */
	public boolean checkCurveMembership(ECF2mGroupParams params, BigInteger x, BigInteger y){
		
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
	 * checks if the given point is in the given dlog group with the q prime order. 
	 * A point is in the group if it in the q-order group which is a sub-group of the Elliptic Curve.
	 * Tha basic assumption of this function is that checkCurveMembership function has already been called and returned true.
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

		// get the curve parameters
		int m = Integer.parseInt(ecProperties.getProperty(curveName));
		int k = Integer.parseInt(ecProperties.getProperty(curveName + "k"));
		String k2Property = ecProperties.getProperty(curveName + "k2");
		String k3Property = ecProperties.getProperty(curveName + "k3");
		BigInteger a = new BigInteger(ecProperties.getProperty(curveName + "a"));
		BigInteger b = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"b")));
		BigInteger x = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"x")));
		BigInteger y = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"y")));
		BigInteger q = new BigInteger(ecProperties.getProperty(curveName + "r"));
		BigInteger h = new BigInteger(ecProperties.getProperty(curveName + "h"));
		
		int k2 = 0;
		int k3 = 0;
		boolean trinomial;
		
		GroupParams groupParams;
		if (k2Property == null && k3Property == null) { // for trinomial basis
			groupParams = new ECF2mTrinomialBasis(q, x, y, m, k, a, b, h);
			trinomial = true;
		} else { // pentanomial basis
			k2 = Integer.parseInt(k2Property);
			k3 = Integer.parseInt(k3Property);
			trinomial = false;
			groupParams = new ECF2mPentanomialBasis(q, x, y, m, k, k2, k3, a, b, h);
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
