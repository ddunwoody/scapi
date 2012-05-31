package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;

import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;

/**
 * This class is a utility class for elliptic curve classes over Fp field.
 * It operates some functionality that is common for every elliptic curve over Fp.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECFpUtility {
	
	/**
	 * Checks if the given x and y represented a valid point on the given curve, 
	 * i.e. if the point (x, y) is a solution of the curve’s equation.
	 * @param params elliptic curve over Fp parameters
	 * @param x coefficient of the point
	 * @param y coefficient of the point
	 * @return true if the given x and y represented a valid point on the given curve
	 */
	public boolean checkCurveMembership(ECFpGroupParams params, BigInteger x, BigInteger y){
		
		/* get a, b, p from group params */
		BigInteger a = params.getA();
		BigInteger b = params.getB();
		BigInteger p = params.getP();
		
		//Calculates the curve equation with the given x,y.
	
		// compute x^3
		BigInteger x3 = x.modPow(new BigInteger("3"), p);
		// compute x^3+ax+b
		BigInteger rightSide = x3.add(a.multiply(x)).add(b).mod(p);
		// compute y^2
		BigInteger leftSide = y.modPow(new BigInteger("2"), p);

		// if the the equation is solved - the point is in the elliptic curve and return true
		if (leftSide.equals(rightSide))
			return true;
		else return false;
	}
	
	/**
	 * checks if the given point is in the given dlog group with the q prime order. 
	 * A point is in the group if it in the q-order group which is a sub-group of the Elliptic Curve.
	 * Base assumption of this function is that checkCurveMembership function is already been called and returned true.
	 * @param curve
	 * @param point
	 * @return true if the given point is in the given dlog group.
	 */
	public boolean checkSubGroupMembership(DlogECFp curve, ECFpPoint point){
		//we assume that the point is on the curve group
		//get the cofactor of the group
		ECFpGroupParams params = (ECFpGroupParams) curve.getGroupParams();
		BigInteger h = params.getCofactor();
		
		//if the cofactor is 1 the sub-group is same as the elliptic curve equation which the point is in.
		if (h.equals(BigInteger.ONE)){
			return true;
		}
		
		BigInteger y = point.getY();
		
		//if the cofactor is greater than 1, the point must have order q (same as the order of the group)
		
		//if the cofactor is 2 and the y coefficient is 0, the point has order 2 and is not in the group
		if (h.equals(new BigInteger("2"))){
			if (y.equals(BigInteger.ZERO)){
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
		
		// if the cofactor is 4, the point has order 2 if the y coefficient of the point is 0, 
		// or the the point has order 4 if the y coefficient of the point raised to two is 0.
		// in both cases the point is not in the group.
		if (h.equals(new BigInteger("4"))){
			if (y.equals(BigInteger.ZERO)){
				return false;
			}
			GroupElement power = curve.exponentiate(point, new BigInteger("2"));
			BigInteger powerY = ((ECElement) power).getY();
			if (powerY.equals(BigInteger.ZERO)){
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

}
