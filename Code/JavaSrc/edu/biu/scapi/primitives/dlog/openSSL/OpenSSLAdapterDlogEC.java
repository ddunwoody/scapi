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
package edu.biu.scapi.primitives.dlog.openSSL;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.primitives.dlog.DlogGroupEC;
import edu.biu.scapi.primitives.dlog.ECElement;

/**
 * An abstract class that implements some common functionalities for both elliptic curve types, Fp and F2m.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class OpenSSLAdapterDlogEC extends DlogGroupEC{

	protected long curve; //Pointer to the native curve.
	
	//Native functions that calls OpenSSL functionalities regarding the curve.
	protected native long createInfinityPoint(long curve);							//Creates an infinity point.
	protected native long inversePoint(long curve, long point);						//Returns the inverse of the given point.
	protected native long exponentiate(long curve, long point, byte[] exponent);	//Raises the given base to the exponent.
	protected native long multiply(long curve, long point1, long point2);			//Multiplies the given points.
	protected native boolean checkCurveMembership(long curve, long point);			//Checks if the given point is on the curve.
	protected native long simultaneousMultiply(long curve, long[] nativePoints, byte[][] exponents);//Raises each base to the respective exponent and multiplies the results.
	protected native boolean validate(long curve);									//Validates the curve.
	protected native long exponentiateWithPreComputedValues(long curve, byte[] exponent);//Raise the given base to the given exponent, using pre computed values.
	protected native void deleteDlog(long curve);									//Deletes the native curve.
	
	/**
	 * Initialize this DlogGroup with the curve in the given file.
	 * @param fileName the file to take the curve's parameters from.
	 * @param curveName name of curve to initialized.
	 * @throws IOException
	 */
	public OpenSSLAdapterDlogEC(String fileName, String curveName) throws IOException {
		this(fileName, curveName, new SecureRandom());
		
	}
	
	/**
	 * Initialize this DlogGroup with the curve in the given file.
	 * @param fileName the file to take the curve's parameters from.
	 * @param curveName name of curve to initialized.
	 * @param random The source of randomness to use.
	 * @throws IOException
	 */
	public OpenSSLAdapterDlogEC(String fileName, String curveName, SecureRandom random) throws IOException {
		super(fileName, curveName, random);
		
	}
	
	/**
	 * Initialize this DlogGroup with one of NIST recommended elliptic curve.
	 * @param curveName name of NIST curve to initialized.
	 * @param random The source of randomness to use.
	 * @throws IOException
	 */
	public OpenSSLAdapterDlogEC(String curveName) throws IOException {
		this(curveName, new SecureRandom());
	}
	
	/**
	 * Initialize this DlogGroup with one of NIST recommended elliptic curve.
	 * @param curveName name of NIST curve to initialized.
	 * @param random The source of randomness to use.
	 * @throws IOException
	 */
	public OpenSSLAdapterDlogEC(String curveName, SecureRandom random) throws IOException {
		this(NISTEC_PROPERTIES_FILE, curveName, random);
	}
	
	/**
	 * @return the native curve.
	 */
	long getCurve(){
		return curve;
	}
	
	@Override
	@Deprecated
	public ECElement generateElement(BigInteger x, BigInteger y) throws IllegalArgumentException {
		return (ECElement) generateElement(true, x, y);
	}
	
	@Override
	public boolean validateGroup(){
		return validate(curve);
	}
	
	/**
	 * Deletes the related Dlog group object
	 */
	protected void finalize() throws Throwable {

		// Delete from the dll the dynamic allocation.
		deleteDlog(curve);

		super.finalize();
	}
	
	// Upload OpenSSL library.
	static {
		System.loadLibrary("OpenSSLJavaInterface");
	}
}
