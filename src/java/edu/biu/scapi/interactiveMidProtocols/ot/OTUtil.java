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
package edu.biu.scapi.interactiveMidProtocols.ot;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Utility class used by OT implementations.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTUtil {
	
	/**
	 * Some OT protocols uses the function RAND(w,x,y,z). 
	 * This function defined as follows.<p>
	 *	1.	SAMPLE random values s,t <- {0, . . . , q-1}<p>
	 *	2.	COMPUTE u = w^s * y^t<p>
	 *	3.	COMPUTE v = x^s * z^t<p>
	 *	4.	OUTPUT (u,v)
	 * @param w
	 * @param x
	 * @param y
	 * @param z
	 */
	public static RandOutput rand(DlogGroup dlog, GroupElement w, GroupElement x, GroupElement y, GroupElement z, SecureRandom random){
		//Compute q-1
		BigInteger q = dlog.getOrder();
		BigInteger qMinusOne = q.subtract(BigInteger.ONE);
		
		//Sample random values s,t <- {0, . . . , q-1}
		BigInteger s = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger t = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		//Compute u = w^s * y^t
		GroupElement wToS = dlog.exponentiate(w, s);
		GroupElement yToT = dlog.exponentiate(y, t);
		GroupElement u = dlog.multiplyGroupElements(wToS, yToT);
		
		//Compute v = x^s * z^t
		GroupElement xToS = dlog.exponentiate(x, s);
		GroupElement zToT = dlog.exponentiate(z, t);
		GroupElement v = dlog.multiplyGroupElements(xToS, zToT);
		
		return new RandOutput(u,v);
	}
	
	/**
	 * Holds the output of the above RAND function.
	 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
	 *
	 */
	public static class RandOutput{
		private GroupElement u;
		private GroupElement v;
		
		public RandOutput(GroupElement u, GroupElement v){
			this.u = u;
			this.v = v;
		}

		public GroupElement getU() {
			return u;
		}

		public GroupElement getV() {
			return v;
		}
	}
	
}
