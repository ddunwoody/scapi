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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersenTrapdoor;

import java.math.BigInteger;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.BigIntegerCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.ReceiverCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.TrapdoorReceiverCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.PedersenCommitterCore;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.PerfectlyHidingCT;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class PedersenTrapdoorCTCommitter extends PedersenCommitterCore implements  CTCommitter, PerfectlyHidingCT {

	/**
	 * @param channel
	 * @throws IllegalArgumentException
	 * @throws SecurityLevelException
	 * @throws InvalidDlogGroupException
	 */
	public PedersenTrapdoorCTCommitter(Channel channel){
		super(channel);
	}
	
	public PedersenTrapdoorCTCommitter(Channel channel, DlogGroup dlog) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		super(channel, dlog);
	}

	@Override
	public CommitValue generateCommitValue(byte[] x)  {
		return new BigIntegerCommitValue(new BigInteger(x));
	}
	
	public boolean validate(ReceiverCommitPhaseOutput trap){
		if (!(trap instanceof TrapdoorReceiverCommitPhaseOutput)){
			throw new IllegalArgumentException("the given trapdor should be an instance of TrapdoorReceiverCommitPhaseOutput");
		}
		TrapdoorReceiverCommitPhaseOutput trapdoor = (TrapdoorReceiverCommitPhaseOutput) trap;
		GroupElement gToTrap = dlog.exponentiate(dlog.getGenerator(), trapdoor.getTrap());
		
		if (gToTrap.equals(h)){
			return true;
		}
		return false;
	}
}
