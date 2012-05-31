package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElement.F2m;

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

	/**
	 * Checks if the given x and y represented a valid point on the given curve, 
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
	 * Base assumption of this function is that checkCurveMembership function is already been called and returned true.
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
}
