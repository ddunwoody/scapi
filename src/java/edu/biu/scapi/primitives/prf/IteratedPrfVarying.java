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

import java.util.logging.Level;

import javax.crypto.IllegalBlockSizeException;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.NoMaxException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.prf.bc.BcHMAC;
import edu.biu.scapi.tools.Factories.PrfFactory;

/** 
 * This class is one implementation of pseudorandom function with varying IO, based on any prf with varying input length. <p>
 * The implementation is based on several calls to the underlying Prf and concatenation of the results.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public class IteratedPrfVarying extends PrfVaryingFromPrfVaryingInput {
	
	/**
	 * Default constructor that uses HMac.
	 * @throws FactoriesException 
	 */
	public IteratedPrfVarying() throws FactoriesException{
		this(new BcHMAC());
	}
	
	/** 
	 * Constructor that accepts the name of the underlying prfVaryingInputLength.
	 * @param prfVaryingInputName  the prf to use. 
	 * @throws FactoriesException 
	 */
	public IteratedPrfVarying(String prfVaryingInputName) throws FactoriesException {	
		//get the requested prfVaryingInput from the factory. 
		this((PrfVaryingInputLength) PrfFactory.getInstance().getObject(prfVaryingInputName));
	}
	
	/**
	 * Constructor that accepts the underlying PrfVaryingInputLength.
	 * @param prfVaryingInput the underlying prf varying.
	 */
	public IteratedPrfVarying(PrfVaryingInputLength prfVaryingInput){
		//assigns the prf varying input.
		prfVaryingInputLength = prfVaryingInput;
	}

	/** 
	 * @return the algorithm name - ITERATED_PRF_VARY_INOUT.
	 */
	public String getAlgorithmName() {
		
		return "ITERATED_PRF_VARY_INOUT";
	}

	/** 
	 * Not relevant - the input and the output do not have a fixed size.
	 * @throws NoMaxException
	 */
	public int getBlockSize() throws NoMaxException {
		
		throw new NoMaxException("prp varying has no fixed block size");
	}


	/**
	 * Computes the iterated permutation. <p>
	 * 
	 * The algorithm pseudocode is:
	 * 
	 * outlen = outBytes.length
	 *	x = inBytes
	 *	----------------
	 *	Let m be the smallest integer for which L*m > outlen, where L is the output length of the PrfVaryingInputLength. 
	 *	FOR i = 1 to m 
	 *	compute Yi = PrfVaryingInputLength(k,(x,outlen,i)) [key=k, data=(x,outlen,i)] 
	 *	return the first outlen bits of Y1,…,Ym  
	 * 
	 * This function is necessary since this prf has variable input and output length.
	 * @param inBytes - input bytes to compute
	 * @param inLen - the length of the input array in bytes
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to put the result from
	 * @param outLen - the length of the output array in bytes
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen) {
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		// checks that the offset and length are correct 
		if ((inOff > inBytes.length) || (inOff+inLen > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+outLen > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		int prfLength = prfVaryingInputLength.getBlockSize();            //the output size of the prfVaryingInputLength
		int rounds = (int) Math.ceil((float)outLen / (float)prfLength);  //the smallest integer for which rounds * prfLength > outlen
		byte[] intermediateOutBytes = new byte[prfLength];               //round result
		byte[] currentInBytes = new byte[inLen+2];                       //the data for the prf 
		
		Integer outLenByte = new Integer(outLen);
		
		//copies the x (inBytes) to the input of the prf in the beginning
		System.arraycopy(inBytes, inOff, currentInBytes, 0, inLen);
		//copies the outLen to the input of the prf after the x
		currentInBytes[inLen] = outLenByte.byteValue();
		
		Integer round;
		
		for(int i=1; i<=rounds; i++) {
			
			round = new Integer(i);
			
			//copies the i to the input of the prf
			currentInBytes[inLen+1] = round.byteValue();
			
			//operates the computeBlock of the prf to get the round output
			try {
				prfVaryingInputLength.computeBlock(currentInBytes, 0, currentInBytes.length, intermediateOutBytes, 0);
			} catch (IllegalBlockSizeException e) {
				Logging.getLogger().log(Level.WARNING, e.toString());
			}
			
			
			if (i==rounds) { //copies the round result to the output byte array
				//in case of the last round - copies only the number of bytes left to match outLen
				System.arraycopy(intermediateOutBytes, 0, outBytes, outOff+(i - 1)*prfLength, outLen-((i-1)*prfLength));
			} else { //in other cases - copies all the result bytes
				System.arraycopy(intermediateOutBytes, 0, outBytes, outOff+(i-1)*prfLength, prfLength);
			}
		}
	}

	
}
