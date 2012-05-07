package edu.biu.scapi.primitives.dlog.bc;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import edu.biu.scapi.primitives.dlog.DlogEllipticCurve;
import edu.biu.scapi.primitives.dlog.DlogGroupEC;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECGroupParams;

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
		super(fileName, curveName);
	}

	/*
	 * Creates an ECPoint from the given x,y
	 * @param x
	 * @param y
	 * @return ECPoint - the created point
	 */
	public ECPoint createPoint(BigInteger x, BigInteger y){
		
		return curve.createPoint(x, y, false);
	}
	
	/*
	 * Checks if the given element is a member of this Dlog group
	 * @param element - 
	 * @return true if the given element is member of this group; false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) throws IllegalArgumentException{
		
		if (!(element instanceof ECPointBc)){
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		
		//infinity point is a valid member
		if (((ECPointBc) element).isInfinity()){
			return true;
		}
		
		ECPointBc point = (ECPointBc)element;
		//checks the validity of the point
		return point.checkValidity(point.getPoint().getX().toBigInteger(), point.getPoint().getY().toBigInteger(), (ECGroupParams)groupParams);
		
		
	}
	
	/*
	 * Calculates the inverse of the given GroupElement
	 * @param groupElement to inverse
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 */
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException{
		
		//if the GroupElement doesn't match the DlogGroup, throws exception
		if (!(groupElement instanceof ECPointBc)){
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
		if (!(base instanceof ECPointBc)){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}
		
		//infinity remains the same after any exponentiate
		if (((ECPointBc) base).isInfinity()){
			return base;
		}
		
		//gets the ECPoint
		ECPoint point = ((ECPointBc)base).getPoint();
		
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
	 * @throws UnInitializedException 
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1, 
						GroupElement groupElement2) throws IllegalArgumentException{
		
		//if the GroupElements don't match the DlogGroup, throws exception
		if (!(groupElement1 instanceof ECPointBc)){
			throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
		}
		if (!(groupElement2 instanceof ECPointBc)){
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
		
		//Our test results show that for BC elliptic curve the LL algorithm always gives the best performances
		return computeLL(groupElements, exponentiations);
	}
	
	/*
	 * Each of the concrete classes implements this function.
	 * BcDlogECFp creates an ECPoint.Fp
	 * BcDlogECF2m creates an ECPoint.F2m
	 */
	protected abstract GroupElement createPoint(ECPoint result);

}
