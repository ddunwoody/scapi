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
import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.pedersenCmtKnowledge.SigmaPedersenCmtKnowledgeProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.pedersenCmtKnowledge.SigmaPedersenCmtKnowledgeProverInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.pedersenCommittedValue.SigmaPedersenCommittedValueProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.pedersenCommittedValue.SigmaPedersenCommittedValueProverInput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtWithProofsCommitter;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKPOKFromSigmaCmtPedersenProver;
import edu.biu.scapi.primitives.dlog.DlogGroup;

/**
 * Concrete implementation of committer with proofs.
 * This implementation uses ZK based on SigmaPedersenKnowledge and SIgmaPedersenCommittedValue.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CmtPedersenWithProofsCommitter extends CmtPedersenCommitter implements CmtWithProofsCommitter{

	//Proves that the committer knows the committed value.
	private ZKPOKFromSigmaCmtPedersenProver knowledgeProver;
	//Proves that the committed value is x.
	//Usually, if the commitment scheme is PerfectlyBinding secure, than a ZK is used to prove committed value.
	//In Pedersen, this is not the case since Pedersen is not PerfectlyBinding secure.
	//In order to be able to use the Pedersen scheme we need to prove committed value with ZKPOK instead.
	private ZKPOKFromSigmaCmtPedersenProver committedValProver;
	
	/**
	 * Default constructor that gets the channel and creates the ZK provers with default Dlog group.
	 * @param channel
	 * @throws ClassNotFoundException if there was a problem in the serialization.
	 * @throws IOException if there was a problem in the communication level.
	 * @throws CheatAttemptException if the committer suspects the receiver try to cheat.
	 */
	public CmtPedersenWithProofsCommitter(Channel channel) throws ClassNotFoundException, IOException, CheatAttemptException {
		super(channel);
		String statisticalParameter = ScapiDefaultConfiguration.getInstance().getProperty("StatisticalParameter");
		int t = Integer.parseInt(statisticalParameter);
		doConstruct(t);
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
	public CmtPedersenWithProofsCommitter(Channel channel, DlogGroup dlog, int t, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException{
		super(channel, dlog, random);	
		doConstruct(t);
	}
	
	/**
	 * Creates the ZK provers using sigma protocols that prove Pedersen's proofs.
	 * @param t
	 * @throws IOException if there was a problem in the communication
	 */
	private void doConstruct(int t) throws IOException{
		SigmaProverComputation pedersenCommittedValProver = new SigmaPedersenCommittedValueProverComputation(dlog, t, random);
		SigmaProverComputation pedersenCTKnowledgeProver = new SigmaPedersenCmtKnowledgeProverComputation(dlog, t, random);
		knowledgeProver = new  ZKPOKFromSigmaCmtPedersenProver(channel, pedersenCTKnowledgeProver);
		committedValProver = new ZKPOKFromSigmaCmtPedersenProver(channel, pedersenCommittedValProver);
		
	}

	@Override
	public void proveKnowledge(long id) throws IOException, CheatAttemptException, ClassNotFoundException {
		CmtPedersenCommitmentPhaseValues val = getCommitmentPhaseValues(id);
		SigmaPedersenCmtKnowledgeProverInput input = new SigmaPedersenCmtKnowledgeProverInput(getPreProcessValues()[0], val.getComputedCommitment(), (BigInteger)val.getX().getX(), val.getR().getR());
		knowledgeProver.prove(input);
	}

	@Override
	public void proveCommittedValue(long id) throws IOException, CheatAttemptException, ClassNotFoundException, CommitValueException {
		CmtPedersenCommitmentPhaseValues val = getCommitmentPhaseValues(id);
		//Send s1 to P2
		try {
			channel.send(val.getX().generateSendableData());
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}
		SigmaPedersenCommittedValueProverInput input = new SigmaPedersenCommittedValueProverInput(getPreProcessValues()[0], val.getComputedCommitment(), (BigInteger)val.getX().getX(), val.getR().getR());
		committedValProver.prove(input);
	}

}
