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


package edu.biu.scapi.primitives.dlog.miracl;

import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;

import edu.biu.scapi.primitives.dlog.DlogEllipticCurve;
import edu.biu.scapi.primitives.dlog.DlogGroupEC;
import edu.biu.scapi.primitives.dlog.GroupElement;

public abstract class MiraclAdapterDlogEC extends DlogGroupEC 
										  implements DlogEllipticCurve{
	
	// upload MIRACL library
	static {
		System.loadLibrary("MiraclJavaInterface");
	}

	
	//Native code functions:
	private native long createMip();
	private native void deleteMip(long mip);
	
	//Class members:
	protected int window = 0;
	protected long mip; ///MIRACL pointer
	protected HashMap <GroupElement, Long> exponentiationsMap; // Map that holds a pointer to the precomputed values of exponentiating a given group element (the base) 
																//calculated in Miracl's native code
	
	
	//temp member variable used for debug:
	PrintWriter file;

	
	//Functions:
	protected MiraclAdapterDlogEC(){}
	
	public MiraclAdapterDlogEC(String fileName, String curveName) throws IOException {
		this(fileName, curveName, new SecureRandom());
	}
	
	public MiraclAdapterDlogEC(String fileName, String curveName, SecureRandom random) throws IOException {
		super(fileName, curveName, random);
		exponentiationsMap = new HashMap <GroupElement, Long>();
	}

	protected abstract boolean basicAndInfinityChecksForExpForPrecomputedValues(GroupElement base);
	protected abstract long initExponentiateWithPrecomputedValues(GroupElement baseElement, BigInteger exponent, int window, int maxBits);
	protected abstract GroupElement computeExponentiateWithPrecomputedValues(long ebrickPointer, BigInteger exponent);
	
	/*
	 * 
	 * @return mip - miracl pointer
	 */
	public long getMip(){
		if (mip==0)
			mip = createMip();
		return mip;
	}
	
	public void setWindow(int val){
		window = val;
	}
	
	
	public GroupElement exponentiateWithPreComputedValues(GroupElement base, BigInteger exponent) {
		//This function performs basic checks on the group element, such as if it is of the right type for the relevant Dlog and checks if the 
		//base group element is the infinity. If so, then the result of exponentiating is the base group element itself, return it.
		boolean infinity = basicAndInfinityChecksForExpForPrecomputedValues(base);
		if (infinity){
			return base;
		}
		//Look for the base in the map. If this is the first time we calculate the exponentiations for this base then:
		//1) we will not find the base in the map
		//2) we need to perform the pre-computation for this base
		//3) and then save the pre-computation for this base in the map
		Long ebrickPointer = exponentiationsMap.get(base);
		//If didn't find the pointer for the base element, create one:
		if(ebrickPointer == null){
			//the actual pre-computation is performed by Miracl. The call to this function returns a pointer to an "ebrick"
			//structure created and held by the Miracl code. We save this pointer in the map for the current base and pass it on
			//to the actual computation of the exponentiation in the step below.
			ebrickPointer = initExponentiateWithPrecomputedValues(base, exponent, getWindow(), getOrder().bitLength());
			exponentiationsMap.put(base, ebrickPointer);
		}
		//At this stage we have a pointer to the ebrick pointer in native code, and we pass it on to compute base^exponent and obtain the resulting Group Element
		return computeExponentiateWithPrecomputedValues(ebrickPointer, exponent);

	}
	
		
	//The window size is used when calling Miracl's implementation of exponentiate with pre-computed values. It is used as part of the Ebrick algorithm.
	protected int getWindow(){
		if (window != 0){
			return window;
		}
		int bits = getOrder().bitLength();
		if (bits <= 256){
			window =  8;
		} else {
			window = 10;
		}
		return window;
	}
	
	/**
	 * deletes the related Dlog group object
	 */
	public void finalize() throws Throwable {

		// delete from the dll the dynamic allocation of MIRACL pointer.
		deleteMip(mip);

		super.finalize();
	}
	
}

