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
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.securityLevel.Malicious;
import edu.biu.scapi.securityLevel.StandAlone;

/**
 * This class plays as party two of coin tossing Blum protocol, which tosses a single bit. <p>
 * This protocol is fully secure under the stand-alone simulation-based definitions.<p>
 * 
 * For more information see M. Blum. Coin Flipping by Phone. IEEE COMPCOM, 1982.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 6.1 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CTBlumPartyTwo implements CTPartyTwo, StandAlone, Malicious{

	private Channel channel;
	private SecureRandom random;
	private CmtReceiver receiver;
	
	/**
	 * Constructor that sets the given values.
	 * @param channel to use in the communication phase
	 * @param receiver the underlying receiver used in this protocol
	 * @param random source of randomness.
	 */
	public CTBlumPartyTwo(Channel channel, CmtReceiver receiver, SecureRandom random){
		this.channel = channel;
		this.random = random;
		this.receiver = receiver;
	}

	/**
	 * Execute the following protocol: <p>
	 * "SAMPLE a random bit b2 <- {0,1} <p>
	 *	WAIT for COMMIT.commit on b1 <p>
	 *	SEND b2 to P1 <p>
	 *	RUN subprotocol COMMIT.decommit to receive b1 <p>
	 *	IF COMMIT.decommit returns INVALID
	 *	      REPORT ERROR (cheat attempt) <p>
	 *	ELSE
	 *	      OUTPUT b1 XOR b2."
	 */
	public CTOutput toss() throws ClassNotFoundException, IOException, CommitValueException, CheatAttemptException {
		//We represent bit in byte, which is the smallest data type in java.
		byte b2;
		//Sample a bit by sample a byte and take the last bit of it.
		byte[] bytesToSample = new byte[1];
		random.nextBytes(bytesToSample);
		//By computing bit AND with 0x01 we determine the last bit.
		if ((bytesToSample[0] & 0x01) == 1){ 
			b2 = 1;
		} else{
			b2 = 0;
		}
				
		//Wait for COMMIT.commit on b1.
		long id = receiver.receiveCommitment().getCommitmentId();
		
		//Send b2 to party one.
		try {
			channel.send(b2);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}
		
		//Run subprotocol COMMIT.decommit to receive b1
		CmtCommitValue commitVal = receiver.receiveDecommitment(id);
		byte b1 = receiver.generateBytesFromCommitValue(commitVal)[0];
		
		return new CTBitOutput((byte) (b1 ^ b2));
	}
	
}
