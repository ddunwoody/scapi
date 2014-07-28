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
package edu.biu.scapi.interactiveMidProtocols.coinTossing;

import java.io.IOException;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.securityLevel.Malicious;
import edu.biu.scapi.securityLevel.StandAlone;

/**
 * This class plays as party one of coin tossing Blum protocol, which tosses a single bit. <p>
 * This protocol is fully secure under the stand-alone simulation-based definitions.<P>
 * 
 * For more information see M. Blum. Coin Flipping by Phone. IEEE COMPCOM, 1982.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 6.1 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CTBlumPartyOne implements CTPartyOne, StandAlone, Malicious{

	private Channel channel;
	private SecureRandom random;
	private CmtCommitter committer;
	
	/**
	 * Constructor that sets the given values.
	 * @param channel to use in the communication phase
	 * @param committer the underlying committer used in this protocol
	 * @param random source of randomness.
	 */
	public CTBlumPartyOne(Channel channel, CmtCommitter committer, SecureRandom random){
		this.channel = channel;
		this.random = random;
		this.committer = committer;
	}

	/**
	 * Execute the following protocol: <p>
	 * "SAMPLE a random bit b1 <- {0,1} <p>
	 *	RUN sub protocol COMMIT.commit on b1<p>
	 *	WAIT for a bit b2 from P2<p>
	 *	RUN sub protocol COMMIT.decommit to reveal b1<p>
	 *	OUTPUT b1 XOR b2."
	 */
	public CTOutput toss() throws IOException, CommitValueException, CheatAttemptException, ClassNotFoundException {
		//We represent bit in byte, which is the smallest data type in java.
		byte b1;
		//Sample a bit by sample a byte and take the last bit of it.
		byte[] bytesToSample = new byte[1];
		random.nextBytes(bytesToSample);
		//By computing bit AND with 0x01 we determine the last bit.
		if ((bytesToSample[0] & 0x01) == 1){ 
			b1 = 1;
		} else{
			b1 = 0;
		}
				
		//Run sub protocol COMMIT.commit on b1.
		long id = random.nextLong();
		byte[] b1ToArray = new byte[1];
		b1ToArray[0] = b1;
		CmtCommitValue commitVal = committer.generateCommitValue(b1ToArray);
		committer.commit(commitVal , id);
		
		//Receive b2 from party two.
		byte b2;
		try {
			b2 = (Byte) channel.receive();
		} catch (IOException e) {
			throw new IOException("Failed to receive b2. The thrown message is: " + e.getMessage());
		}
		
		//RUN sub protocol COMMIT.decommit to reveal b1
		committer.decommit(id);
		
		return new CTBitOutput((byte) (b1 ^ b2));
	}
	
	
}
