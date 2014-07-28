/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
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

package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtBigIntegerCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtOnBigInteger;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.securityLevel.PerfectlyHidingCmt;

/**
 * Concrete implementation of committer that executes the Pedersen commitment scheme in the committer's point of view.<p>
 * 
 * For more information see Protocol 6.5.3, page 164 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 3.1 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CmtPedersenCommitter extends CmtPedersenCommitterCore implements CmtCommitter, PerfectlyHidingCmt, CmtOnBigInteger {
		
	/**
	 * Constructor that receives a connected channel (to the receiver) and chooses default dlog and random. 
	 * The receiver needs to be instantiated with the default constructor too.
	 * @param channel
	 * @throws ClassNotFoundException in case there was a problem in the serialization in the preprocess phase.
	 * @throws IOException in case there was a problem in the communication in the preprocess phase.
	 * @throws CheatAttemptException in case the committer suspects the receiver cheated in the preprocess phase.
	 */
	public CmtPedersenCommitter(Channel channel) throws ClassNotFoundException, IOException, CheatAttemptException {
		super(channel);
	}
	
	/**
	 * Constructor that receives a connected channel (to the receiver), the DlogGroup agreed upon between them and a SecureRandom object.
	 * The Receiver needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	 * @param channel
	 * @param dlog
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given dlog is not valid.
	 * @throws ClassNotFoundException if there was a problem in the serialization
	 * @throws IOException if there was a problem in the communication
	 * @throws CheatAttemptException if the receiver h is not in the DlogGroup.
	 */
	public CmtPedersenCommitter(Channel channel, DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException{
		super(channel, dlog, random);	
	}

	@Override
	public CmtCommitValue generateCommitValue(byte[] x)  {
		//In case that x is negative, pad the byte array with the byte '1' to make it positive.
		//This is also solve the case that the first byte in x is zero. 
		//In that case the conversion to BigInteger ignores the first byte and therefore 
		//the conversion back to byte array is wrong.
		byte[] positiveArr = new byte[x.length + 1];
		positiveArr[0] = 1;
		System.arraycopy(x, 0, positiveArr, 1, x.length);

		return new CmtBigIntegerCommitValue(new BigInteger(positiveArr));
	}
	
	/**
	 * This function converts the given commit value to a byte array. 
	 * @param value
	 * @return the generated bytes.
	 */
	public byte[] generateBytesFromCommitValue(CmtCommitValue value){
		if (!(value instanceof CmtBigIntegerCommitValue))
			throw new IllegalArgumentException("The given value must be of type CmtBigIntegerCommitValue");
		//Remove the first byte of BigInteger in order to get the original x.
		byte[] biBytes = ((BigInteger)value.getX()).toByteArray();
		byte[] x = new byte[biBytes.length - 1];
		System.arraycopy(biBytes, 1, x, 0, biBytes.length - 1);
		return x;
	}
	
	/**
	 * This function samples random commit value and returns it.
	 * @return the sampled commit value
	 */
	public CmtCommitValue sampleRandomCommitValue(){
		BigInteger qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
		BigInteger val = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		return new CmtBigIntegerCommitValue(val);
	}
	
}
