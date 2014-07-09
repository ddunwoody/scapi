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

import java.io.IOException;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtOnBigInteger;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtRCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtRTrapdoorCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.CmtPedersenCommitter;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.PerfectlyHidingCmt;

/**
 * Concrete implementation of committer that executes the Pedersen trapdoor commitment 
 * scheme in the committer's point of view.<p>
 * 
 * This commitment is also a trapdoor commitment in the sense that the receiver after 
 * the commitment phase has a trapdoor value, that if known by the committer would enable
 * it to decommit to any value. <p>
 * 
 * This trapdoor is output by the receiver and can be used by a higher-level application 
 * (e.g., by the ZK transformation of a sigma protocol to a zero-knowledge proof of knowledge).<p>
 * 
 * For more information see Protocol 6.5.3, page 164 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 3.3 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CmtPedersenTrapdoorCommitter extends CmtPedersenCommitter implements  CmtCommitter, PerfectlyHidingCmt, CmtOnBigInteger{

	/**
	 * Constructor that receives a connected channel (to the receiver) and chooses default dlog and random. 
	 * The receiver needs to be instantiated with the default constructor too.
	 * @param channel
	 * @throws ClassNotFoundException in case there was a problem in the serialization in the preprocess phase.
	 * @throws IOException in case there was a problem in the communication in the preprocess phase.
	 * @throws CheatAttemptException in case the committer suspects the receiver cheated in the preprocess phase.
	 */
	public CmtPedersenTrapdoorCommitter(Channel channel) throws ClassNotFoundException, IOException, CheatAttemptException{
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
	public CmtPedersenTrapdoorCommitter(Channel channel, DlogGroup dlog, SecureRandom random) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException{
		super(channel, dlog, random);
	}
	
	/**
	 * Validate the h value received from the receiver in the pre process phase.
	 * @param trap the trapdoor outputed from the receiver's commit phase.
	 * @return true, if valif; false, otherwise.
	 */
	public boolean validate(CmtRCommitPhaseOutput trap){
		if (!(trap instanceof CmtRTrapdoorCommitPhaseOutput)){
			throw new IllegalArgumentException("the given trapdor should be an instance of CmtRTrapdoorCommitPhaseOutput");
		}
		
		//Check that g^trapdoor equals to h.
		CmtRTrapdoorCommitPhaseOutput trapdoor = (CmtRTrapdoorCommitPhaseOutput) trap;
		GroupElement gToTrap = dlog.exponentiate(dlog.getGenerator(), trapdoor.getTrap());
		
		if (gToTrap.equals(h)){
			return true;
		}
		return false;
	}
}
