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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.pedersenCmtKnowledge.SigmaPedersenCmtKnowledgeCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.pedersenCmtKnowledge.SigmaPedersenCmtKnowledgeVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.pedersenCommittedValue.SigmaPedersenCommittedValueCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.pedersenCommittedValue.SigmaPedersenCommittedValueVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtBigIntegerCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtWithProofsReceiver;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKPOKFromSigmaCmtPedersenVerifier;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of receiver with proofs.
 * This implementation uses ZK based on SigmaPedersenKnowledge and SIgmaPedersenCommittedValue.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CmtPedersenWithProofsReceiver extends CmtPedersenReceiver implements CmtWithProofsReceiver{

	//Verifies that the committer knows the committed value.
	private ZKPOKFromSigmaCmtPedersenVerifier knowledgeVerifier;
	//Verifies that the committed value is x.
	//Usually, if the commitment scheme is PerfectlyBinding secure, than a ZK is used to verify committed value.
	//In Pedersen, this is not the case since Pedersen is not PerfectlyBinding secure.
	//In order to be able to use the Pedersen scheme we need to verify committed value with ZKPOK instead.
	private ZKPOKFromSigmaCmtPedersenVerifier committedValVerifier;
	
	/**
	 * Default constructor that gets the channel and creates the ZK verifiers with default Dlog group.
	 * @param channel
	 * @throws ClassNotFoundException if there was a problem in the serialization.
	 * @throws IOException if there was a problem in the communication level.
	 * @throws CheatAttemptException if the receiver suspects the committer try to cheat.
	 */
	public CmtPedersenWithProofsReceiver(Channel channel) throws ClassNotFoundException, IOException, CheatAttemptException {
		super(channel);
		String statisticalParameter = ScapiDefaultConfiguration.getInstance().getProperty("StatisticalParameter");
		int t = Integer.parseInt(statisticalParameter);
		try {
			doConstruct(t);
		} catch (InvalidDlogGroupException e) {
			//Should not occur since the default dlog is valid.
		}
	}
	
	/**
	 * Constructor that gets the channel, dlog, statistical parameter and random and uses them to create the ZK provers.
	 * @param channel
	 * @param dlog
	 * @param t statistical parameter
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given dlog is not valid.
	 * @throws ClassNotFoundException if there was a problem in the serialization
	 * @throws IOException if there was a problem in the communication
	 * @throws CheatAttemptException if the receiver h is not in the DlogGroup.
	 */
	public CmtPedersenWithProofsReceiver(Channel channel, DlogGroup dlog, int t, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException{
		super(channel, dlog, random);	
		doConstruct(t);
	}
	
	/**
	 * Creates the ZK verifiers using sigma protocols that verifies Pedersen's proofs.
	 * @param t
	 * @throws IOException Creates the ZK provers using sigma protocols that prove Pedersen's proofs.
	 * @throws InvalidDlogGroupException if the given dlog is not valid.
	 * @throws CheatAttemptException if the receiver h is not in the DlogGroup.
	 * @throws ClassNotFoundException if there was a problem in the serialization
	 */
	private void doConstruct(int t) throws IOException, InvalidDlogGroupException, ClassNotFoundException, CheatAttemptException{
		SigmaVerifierComputation pedersenCommittedValVerifier = new SigmaPedersenCommittedValueVerifierComputation(dlog, t, random);
		SigmaVerifierComputation pedersenCTKnowledgeVerifier = new SigmaPedersenCmtKnowledgeVerifierComputation(dlog, t, random);
		knowledgeVerifier = new  ZKPOKFromSigmaCmtPedersenVerifier(channel, pedersenCTKnowledgeVerifier, random);
		committedValVerifier = new ZKPOKFromSigmaCmtPedersenVerifier(channel, pedersenCommittedValVerifier, random);
		
	}

	@Override
	public boolean verifyKnowledge(long id) throws ClassNotFoundException, IOException, CheatAttemptException {
		GroupElement commitmentVal = getCommitmentPhaseValues(id);
		SigmaPedersenCmtKnowledgeCommonInput input =  new SigmaPedersenCmtKnowledgeCommonInput((GroupElement) getPreProcessedValues()[0], commitmentVal);
		return knowledgeVerifier.verify(input);
	}

	@Override
	public CmtBigIntegerCommitValue verifyCommittedValue(long id) throws IOException, ClassNotFoundException, CheatAttemptException, CommitValueException { 
		Serializable x;
		try {
			x = channel.receive();
		} catch (IOException e) {
			throw new IOException("Failed to receive x. The thrown message is: " + e.getMessage());
		}
		if (!(x instanceof BigInteger)){
			throw new IllegalArgumentException("The given x is not an instance of BigInteger");
		}
		GroupElement commitmentVal = getCommitmentPhaseValues(id);
		SigmaPedersenCommittedValueCommonInput input = new SigmaPedersenCommittedValueCommonInput((GroupElement)getPreProcessedValues()[0], commitmentVal, (BigInteger)x);
		boolean verified = committedValVerifier.verify(input);
		if (verified){
			return new CmtBigIntegerCommitValue((BigInteger)x);
		} else{
			return null;
		}
	}
}
