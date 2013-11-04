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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamal;

import java.io.IOException;
import java.io.Serializable;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalCmtKnowledge.SigmaElGamalCmtKnowledgeCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalCmtKnowledge.SigmaElGamalCmtKnowledgeVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalCommittedValue.SigmaElGamalCommittedValueCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalCommittedValue.SigmaElGamalCommittedValueVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtWithProofsReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtGroupElementCommitValue;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKFromSigmaVerifier;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKPOKFromSigmaCmtPedersenVerifier;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ElGamalPublicKey;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

/**
 * Concrete implementation of receiver with proofs.
 * 
 * This implementation uses ZK based on SigmaElGamalKnowledge and SIgmaElGamalCommittedValue.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CmtElGamalWithProofsReceiver extends CmtElGamalOnGroupElementReceiver implements CmtWithProofsReceiver{
	
	//Verifies that the committer knows the committed value.
	private ZKPOKFromSigmaCmtPedersenVerifier knowledgeVerifier;
	//Proves that the committed value is x.
	private ZKFromSigmaVerifier committedValVerifier;
	
	/**
	 * Default constructor that gets the channel and creates the ZK verifiers with default Dlog group.
	 * @param channel
	 * @throws ClassNotFoundException if there was a problem in the serialization.
	 * @throws IOException if there was a problem in the communication level.
	 * @throws CheatAttemptException if the receiver suspects the committer try to cheat.
	 */
	public CmtElGamalWithProofsReceiver(Channel channel) throws IOException, ClassNotFoundException, CheatAttemptException {
		super(channel);
		String statisticalParameter = ScapiDefaultConfiguration.getInstance().getProperty("StatisticalParameter");
		int t = Integer.parseInt(statisticalParameter);
		try {
			doConstruct(t, new SecureRandom());
		} catch (InvalidDlogGroupException e) {
			//Should not occur since the default dlog is valid.
		}
	}
	
	/**
	 * Constructor that gets the channel, dlog, statistical parameter and random and uses
	 * them to create the ZK verifiers.
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
	public CmtElGamalWithProofsReceiver(Channel channel, DlogGroup dlog, int t, SecureRandom random) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException, IOException, ClassNotFoundException, CheatAttemptException {
		super(channel, dlog);	
		doConstruct(t, random);
	}
	
	/**
	 * Creates the ZK verifiers using sigma protocols that verifies ElGamal's proofs.
	 * @param t
	 * @throws IOException Creates the ZK provers using sigma protocols that prove Pedersen's proofs.
	 * @throws InvalidDlogGroupException if the given dlog is not valid.
	 * @throws CheatAttemptException if the receiver h is not in the DlogGroup.
	 * @throws ClassNotFoundException if there was a problem in the serialization
	 */
	private void doConstruct(int t, SecureRandom random) throws IOException, ClassNotFoundException, CheatAttemptException, InvalidDlogGroupException {
		SigmaVerifierComputation elGamalCommittedValVerifier = new SigmaElGamalCommittedValueVerifierComputation(dlog, t, random);
		SigmaVerifierComputation elGamalCTKnowledgeVerifier = new SigmaElGamalCmtKnowledgeVerifierComputation(dlog, t, random);
		knowledgeVerifier = new  ZKPOKFromSigmaCmtPedersenVerifier(channel, elGamalCTKnowledgeVerifier, random);
		committedValVerifier = new ZKFromSigmaVerifier(channel, elGamalCommittedValVerifier, random);
		
	}

	@Override
	public boolean verifyKnowledge(long id) throws IOException, CheatAttemptException, ClassNotFoundException {
		SigmaElGamalCmtKnowledgeCommonInput input =  new SigmaElGamalCmtKnowledgeCommonInput
				((ElGamalPublicKey)getPreProcessedValues()[0]);
		return knowledgeVerifier.verify(input);
	}

	@Override
	public CmtGroupElementCommitValue verifyCommittedValue(long id) throws IOException, CheatAttemptException, ClassNotFoundException, CommitValueException  {
		//Receive the committed value from the committer.
		Serializable x;
		try {
			x = channel.receive();
		} catch (IOException e) {
			throw new IOException("Failed to receive x. The thrown message is: " + e.getMessage());
		}
		if (!(x instanceof GroupElementSendableData)){
			throw new IllegalArgumentException("The received x is not an instance of GroupElementSendableData");
		}
		GroupElement committedVal = dlog.reconstructElement(true, (GroupElementSendableData) x);
		
		//Creates input for the ZK verifier
		CmtElGamalCommitmentMessage commitmentVal = getCommitmentPhaseValues(id);
		SigmaElGamalCommittedValueCommonInput input =  new SigmaElGamalCommittedValueCommonInput
				((ElGamalPublicKey)getPreProcessedValues()[0], commitmentVal.getCommitment(), committedVal);
		//Computes the verification.
		boolean verified = committedValVerifier.verify(input);
		if (verified){
			return new CmtGroupElementCommitValue(committedVal);
		} else{
			return null;
		}
	}
}
