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


package edu.biu.scapi.primitives.prf;

import javax.crypto.IllegalBlockSizeException;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.NoMaxException;
import edu.biu.scapi.tools.Factories.PrfFactory;

/** 
 * The class LubyRackoffPrpFromPrfVarying is one implementation that has a varying input and output length. 
 * LubyRackoffPrpFromPrfVarying is a pseudorandom permutation with varying input/output lengths, based on any PRF with a variable input/output length 
 * (as long as input length = output length). We take the interpretation that there is essentially a different random permutation
 * for every input/output length.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 * 
 */
public final class LubyRackoffPrpFromPrfVarying extends PrpFromPrfVarying {
	
	
	public LubyRackoffPrpFromPrfVarying() throws FactoriesException {

		//default underlying PRF 
		this(new IteratedPrfVarying());
	}
	
		
	/**
	 * Constructor that accepts a name of a prfVaryingIOLength to be the underlying PRF.
	 * @param prfVaryingIOLengthName the underlying PRF name 
	 * @throws FactoriesException
	 */
	public LubyRackoffPrpFromPrfVarying(String prfVaryingIOLengthName) throws FactoriesException {

		//gets the requested prpVarying and random from the factories. 
		//then call the extended constructor
		this((PrfVaryingIOLength) PrfFactory.getInstance().getObject(prfVaryingIOLengthName));
	}
	
	
	/**
	 * Constructor that accepts a prfVaryingIOLength to be the underlying PRF.
	 * @param prfVaryingIOLength the underlying PRF varying.
	 */
	public LubyRackoffPrpFromPrfVarying(PrfVaryingIOLength prfVaryingIOLength){
		
		if(prfVaryingIOLength instanceof LubyRackoffPrpFromPrfVarying){
			throw new IllegalArgumentException("Cannot create a LubyRackoffPrpFromPrfVarying from a LubyRackoffPrpFromPrfVarying object!");
		}
		this.prfVaryingIOLength = prfVaryingIOLength;
		
	}
	
		
	/** 
	 * Computes the LubyRackoff permutation.
	 * the algorithm pseudocode is: 
	 * Input :
	 *		 x = inBytes – should  be of even length                                                      
	 *		-----------------
	 *		Let |x|=2L (i.e., the length of the input is 2L) 
	 *		Let L0 be the first |x|/2 bits of x 
	 *		Let R0 be the second |x|/2 bits of x 
	 *		For i = 1 to 4 
	 *		SET Li = Ri-1 
     *		compute Ri = Li-1 ^ PRF_VARY_INOUT(k,(Ri-1,i),L)  
	 *		[key=k, data=(Ri-1,i),  outlen = L] 
	 *		return (L4,R4) 
	 *
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param inLen the length of the input array and the output array. Since this is a prp, the input and output lengths should be equal.
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to put the result from
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff) throws IllegalBlockSizeException{
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		// checks that the offsets and length are correct 
		if ((inOff > inBytes.length) || (inOff+inLen > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+inLen > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		
		//checks that the input is of even length.
		if(!(inLen % 2==0) ){//odd throw exception
			throw new IllegalBlockSizeException("Length of input must be even");
		}
		
		int sideSize = inLen/2;//L in the pseudo code
		byte[] tmpReference;
		byte[] leftCurrent = new byte[sideSize];
		byte[] rightCurrent = new byte[sideSize+1];//keeps space for the index. Size of L+1. 
		byte[] leftNext = new byte[sideSize];
		byte[] rightNext = new byte[sideSize+1];//keeps space for the index. Size of L+1.
		
			
		//Let left_current be the first half bits of the input
		System.arraycopy(inBytes, inOff, leftCurrent, 0, sideSize);
		
		//Let right_current be the last half bits of the input
		System.arraycopy(inBytes, inOff+sideSize, rightCurrent, 0, sideSize);
		
		for(int i=1; i<=4; i++){
	
			//Li = Ri-1
			System.arraycopy(rightCurrent, 0, leftNext, 0, sideSize);
			
			//put the index in the last position of Ri-1
			rightCurrent[sideSize] = new Integer(i).byteValue();
			
			//does PRF_VARY_INOUT(k,(Ri-1,i),L) of the pseudocode
			//puts the result in the rightNext array. Later we will XOr it with leftCurrent. Note that the result size is not the entire
			//rightNext array. It is one byte less. The remaining byte will contain the index for the next iteration.
			prfVaryingIOLength.computeBlock(rightCurrent, 0, rightCurrent.length, rightNext, 0, sideSize);
			
			//does Ri = Li-1 ^ PRF_VARY_INOUT(k,(Ri-1,i),L)  
			//XOR rightNext (which is the resulting PRF computation by now) with leftCurrent.
			for(int j=0;j<sideSize;j++){
				
				rightNext[j] = (byte) (rightNext[j] ^ leftCurrent[j]); 
			}
			
			
			//switches between the current and the next for the next round.
			//Note that it is much more readable and straightforward to copy the next arrays into the current arrays.
			//However why copy if we can switch between them and avoid the performance increase by copying. We can not just use assignment 
			//Since both current and next will point to the same memory block and thus changing one will change the other.
			tmpReference = leftCurrent;
			leftCurrent = leftNext;
			leftNext = tmpReference;
			
			tmpReference = rightCurrent;
			rightCurrent = rightNext;
			rightNext = tmpReference;
			
		}
		
		//copies the result to the out array.
		System.arraycopy(leftCurrent, 0, outBytes, outOff, inLen/2);
		System.arraycopy(rightCurrent, 0, outBytes, outOff+inLen/2, inLen/2);
		
		
	}

	/** 
	 * Inverts LubyRackoff permutation using the given key. <p>
	 * Since LubyRackoff permutation can also have varying input and output length 
	 * (although the input and the output should be the same length), the common parameter <code>len</code> of the input and the output is needed.
	 * LubyRackoff has a feistel structure and thus invert is possible even though the underlying PRF is not invertible.
	 * The pseudocode for inverting such a structure is the following
	 * FOR i = 4 to 1
     * SET Ri-1 = Li 
     * COMPUTE Li-1 = Ri XOR PRF_VARY_INOUT(k,(Ri-1 (or Li),i),L)    
     *                     [key=k, data=(Ri-1,i), outlen = L]
	 *	OUTPUT (L0,R0)
	 * 
	 * @param inBytes input bytes to invert.
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert
	 * @param outOff output offset in the outBytes array to put the result from
	 * @param len the length of the input and the output
	 * @throws IllegalBlockSizeException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff, int len) throws IllegalBlockSizeException{
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		// checks that the offset and length are correct 
		if ((inOff > inBytes.length) || (inOff+len > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+len > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		//checks that the input is of even length.
		if(!(len % 2==0) ){//odd throw exception
			throw new IllegalBlockSizeException("Length of input must be even");
		}
		
		int sideSize = len/2;//L in the pseudo code
		byte[] tmpReference;
		byte[] leftCurrent = new byte[sideSize];
		byte[] rightCurrent = new byte[sideSize+1];//keeps space for the index. Size of L+1. 
		byte[] leftNext = new byte[sideSize];
		byte[] rightNext = new byte[sideSize+1];//keeps space for the index. Size of L+1.
		
			
		//Let leftNext be the first half bits of the input
		System.arraycopy(inBytes, inOff, leftNext, 0, sideSize);
		
		//Let rightNext be the last half bits of the input
		System.arraycopy(inBytes, inOff+sideSize, rightNext, 0, sideSize);
		
		for(int i=4; i>=1; i--){
			
			//Ri-1 = Li
			System.arraycopy(leftNext, 0, rightCurrent, 0, sideSize);
			
			//completes Ri-1 = Ri-1|i 
			rightCurrent[sideSize] = new Integer(i).byteValue();
			
			//does PRF_VARY_INOUT(k,(Ri-1,i),L) of the pseudocode
			//puts the result in the leftCurrent array. Later we will XOr it with rightNext. 
			prfVaryingIOLength.computeBlock(rightCurrent, 0, rightCurrent.length, leftCurrent, 0, sideSize);
			
			//does Li-1 = Ri ^ PRF_VARY_INOUT(k,(Ri-1,i),L)  
			//XOR leftCurrent (which is the resulting PRF computation by now) with rightNext.
			for(int j=0;j<sideSize;j++){
				
				leftCurrent[j] = (byte) (leftCurrent[j] ^ rightNext[j]); 
			}
			
			
			//switches between the current and the next for the next round.
			//Note that it is much more readable and straightforward to copy the next arrays into the current arrays.
			//However why copy if we can switch between them and avoid the performance increase by copying. We can not just use assignment 
			//Since both current and next will point to the same memory block and thus changing one will change the other.
			tmpReference = leftNext;
			leftNext = leftCurrent;
			leftCurrent = tmpReference;
			
			tmpReference = rightNext;
			rightNext = rightCurrent;
			rightCurrent = tmpReference;
			
		}
		
		//copies the result to the out array.
		System.arraycopy(leftNext, 0, outBytes, outOff, sideSize);
		System.arraycopy(rightNext, 0, outBytes, outOff+sideSize, sideSize);
		
	}

	/**
	 * @return LubyRackoff algorithm name
	 */
	public String getAlgorithmName() {
		return "LUBY_RACKOFF_PRP_FROM_PRF_VARYING";
	}

	/**
	 * This object has varying input/output lengths, so this function shouldn't be called.
	 * @throws NoMaxException
	 */
	public int getBlockSize() throws NoMaxException {
		throw new NoMaxException("prp varying has no fixed block size");
	}


}
