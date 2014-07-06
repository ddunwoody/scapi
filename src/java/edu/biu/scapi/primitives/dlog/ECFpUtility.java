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
import java.security.SecureRandom;
import java.util.Properties;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElement.Fp;
import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

/**
 * This class is a utility class for elliptic curve classes over Fp field.
 * It operates some functionality that is common for every elliptic curve over Fp.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECFpUtility {


	/**
	 * Default constructor.
	 */
	public ECFpUtility() {
		super();
	}


	/**
	 * Checks if the given x and y represent a valid point on the given curve, 
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
	 * This function finds the y coordinate of a point in the curve for a given x, if it exists.
	 * @param params the parameters of the group
	 * @param x
	 * @return the y coordinate of point in the curve for a given x, if it exists
	 * 			else, null
	 */
	public BigInteger findYInCurveEquationForX(ECFpGroupParams params, BigInteger x){

		/* get a, b, p from group params */
		BigInteger a = params.getA();
		BigInteger b = params.getB();
		BigInteger p = params.getP();


		// compute x^3
		BigInteger x3 = x.modPow(new BigInteger("3"), p);
		// compute x^3+ax+b
		BigInteger rightSide = x3.add(a.multiply(x)).add(b).mod(p);
		//try to compute y = square_root(x^3+ax+b)
		//If it exists return it
		//else, return null
		//We compute the square root via the ECFieldElement.Fp of Bouncy Castle, since BigInteger does not implement this function.
		//ECFieldElement.Fp ySquare = new ECFieldElement.Fp(params.getQ(), rightSide);
		ECFieldElement.Fp ySquare = new ECFieldElement.Fp(params.getP(), rightSide);

		//TODO I am not sure which one of the square roots it returns (if they exist). We need to check this!! (Yael)
		ECFieldElement.Fp y = (Fp) ySquare.sqrt();
		if(y != null){
			return y.toBigInteger().mod(p);
		}
		else {
			return null;
		}
	}

	//Auxiliary class used to hold the (x,y) coordinates of a point.It does not have any information about the curve and any further checks regarding membership
	//to any specific curve should be performed by the user of this auxiliary class.
	public class FpPoint {
		BigInteger x;
		BigInteger y;

		public FpPoint(BigInteger x, BigInteger y){
			this.x = x;
			this.y = y;
		}

		public BigInteger getX() {
			return x;
		}

		public BigInteger getY() {
			return y;
		}

	}


	/**
	 * This function receives any string of size up to k bytes (as returned by CalcK), finds the coordinates of the point that is the encoding of this binary string.
	 * @param binaryString
	 * @throws IndexOutOfBoundsException if the length of the binary array to encode is longer than k
	 * @return an FpPoint with the coordinates of the corresponding GroupElement point or null if could not find the encoding in reasonable time 
	 */
	public FpPoint findPointRepresentedByByteArray(ECFpGroupParams params, byte[] binaryString, int k ){
	
		//Pseudo-code:
		/*If the length of binaryString exceeds k then throw IndexOutOfBoundsException.

          Let L be the length in bytes of p

          Choose a random byte array r of length L – k – 2 bytes 

          Prepare a string newString of the following form: r || binaryString || binaryString.length (where || denotes concatenation) (i.e., the least significant byte of newString is the length of binaryString in bytes)

          Convert the result to a BigInteger (bIString)

          Compute the elliptic curve equation for this x and see if there exists a y such that (x,y) satisfies the equation.

          If yes, return (x,y)

          Else, go back to step 3 (choose a random r etc.) up to 80 times (This is an arbitrary hard-coded number).

          If did not find y such that (x,y) satisfies the equation after 80 trials then return null.
		 */


		if (binaryString.length > k){
			throw new IndexOutOfBoundsException("The binary array to encode is too long.");
		}


		int l = params.getP().bitLength()/8;
		byte[] randomArray = new byte[l-k-2];
		//Create a random object and make it seed itself: 
		SecureRandom rand = new SecureRandom();

		byte[] newString = new byte[randomArray.length + 1 + binaryString.length];
		int counter = 0;
		BigInteger y = null;
		BigInteger x = null;
		do{
			rand.nextBytes(randomArray);
			System.arraycopy(randomArray, 0, newString, 0, randomArray.length);
			System.arraycopy(binaryString, 0, newString, randomArray.length , binaryString.length);
			newString[newString.length-1] = (byte) binaryString.length;
			//Convert the result to a BigInteger (bIString)
			x = new BigInteger(newString);
			if(x.compareTo(BigInteger.ZERO) < 0){	
				byte[] temp = x.toByteArray();
				byte t0 = temp[0];
				temp[0] = (byte) -t0;
				x = new BigInteger(temp);
			}

			//Compute the elliptic curve equation for this x and see if there exists a y such that (x,y) satisfies the equation.
			//If yes, return (x,y)
			//Else, go back to choose a random r etc.)
			y = findYInCurveEquationForX(params, x);
			counter++;
		} while((y == null) && (counter <= 80)); //we limit the amount of times we try to 80 which is an arbitrary number.

		//If found the correct y in reasonable time then return the (x,y) FpPoint
		if (y != null)
			return new FpPoint(x,y);
		//Otherwise, return null
		return null;
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

	/**
	 * This function calculates k, the maximum length in bytes of a string to be converted to a Group Element of this group.
	 * @param p
	 * @return k
	 */
	public int calcK(BigInteger p){
		int bitsInp = p.bitLength();
		int k =(int) Math.floor((0.4 * bitsInp)/8) - 1;
		//For technical reasons of how we chose to do the padding for encoding and decoding (the least significant byte of the encoded string contains the size of the 
		//the original binary string sent for encoding, which is used to remove the padding when decoding) k has to be <= 255 bytes so that the size can be encoded in the padding.
		if( k > 255){
			k = 255;
		}
		return k;
	}

	/**
	 * This function returns the k least significant bytes of the number x
	 * @param x
	 * @param k
	 * @return k least significant bits of x
	 */
	public byte[] getKLeastSignBytes(BigInteger x, int k){
		//To retrieve the k least significant bits of a number x we do:
		//lsb = x mod (2^8k)
		BigInteger modulo = BigInteger.valueOf(2).pow(8*k);
		return x.mod(modulo).toByteArray();
	}


	/**
	 * This function receives the name of a curve and some possible properties and it checks that curve is actually a curve over the Fp field. If so, it creates the necessary
	 * GroupParams. Else, throws  IllegalArgumentException.
	 * @param ecProperties
	 * @param curveName
	 * @return the GroupParams if this curve is a curve over the Fp field.
	 * @throws IllegalArgumentException if curveName is not a curve over Fp field and doesn't match the DlogGroup type.
	 */
	public GroupParams checkAndCreateInitParams(Properties ecProperties, String curveName) {
		// check that the given curve is in the field that matches the group
		if (!curveName.startsWith("P-")) {
			throw new IllegalArgumentException( "curveName is not a curve over Fp field and doesn't match the DlogGroup type");
		}
		// get the curve parameters
		BigInteger p = new BigInteger(ecProperties.getProperty(curveName));
		BigInteger a = new BigInteger(ecProperties.getProperty(curveName + "a"));
		BigInteger b = new BigInteger(1, Hex.decode(ecProperties.getProperty(curveName + "b")));
		BigInteger x = new BigInteger(1, Hex.decode(ecProperties.getProperty(curveName + "x")));
		BigInteger y = new BigInteger(1, Hex.decode(ecProperties.getProperty(curveName + "y")));
		BigInteger q = new BigInteger(ecProperties.getProperty(curveName + "r"));
		BigInteger h = new BigInteger(ecProperties.getProperty(curveName + "h"));

		// create the GroupParams
		GroupParams groupParams = new ECFpGroupParams(q, x, y, p, a, b, h);
		return groupParams;
	}
	
	/**
	 * @return the type of the group - ECFp
	 */
	public String getGroupType(){
		return "ECFp";
	}
}
