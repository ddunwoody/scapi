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
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalCmtKnowledge.SigmaElGamalCmtKnowledgeProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalCmtKnowledge.SigmaElGamalCmtKnowledgeProverInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalCommittedValue.SigmaElGamalCommittedValueProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalCommittedValue.SigmaElGamalCommittedValueProverInput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtWithProofsCommitter;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKFromSigmaProver;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKPOKFromSigmaCmtPedersenProver;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ElGamalPublicKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPrivateKey;
import edu.biu.scapi.midLayer.ciphertext.ElGamalCiphertextSendableData;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of committer with proofs.
 * This implementation uses ZK based on SigmaElGamalKnowledge and SIgmaElGamalCommittedValue.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CmtElGamalWithProofsCommitter extends CmtElGamalOnGroupElementCommitter implements CmtWithProofsCommitter{

	//Proves that the committer knows the committed value.
	private ZKPOKFromSigmaCmtPedersenProver knowledgeProver;
	//Proves that the committed value is x.
	private ZKFromSigmaProver committedValProver;
	
	/**
	 * Default constructor that gets the channel and creates the ZK provers with default Dlog group.
	 * @param channel
	 * @throws IOException
	 */
	public CmtElGamalWithProofsCommitter(Channel channel) throws IOException {
		super(channel);
		String statisticalParameter = ScapiDefaultConfiguration.getInstance().getProperty("StatisticalParameter");
		int t = Integer.parseInt(statisticalParameter);
		doConstruct(t, new SecureRandom());
	}
	
	/**
	 * Constructor that gets the channel, dlog, statistical parameter and random and uses them to create the ZK provers.
	 * @param channel
	 * @param dlog
	 * @param t statistical parameter
	 * @param random
	 * @throws IllegalArgumentException
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given dlog is not valid.
	 * @throws IOException if there was a problem in the communication
	 */
	public CmtElGamalWithProofsCommitter(Channel channel, DlogGroup dlog, int t, SecureRandom random) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException, IOException {
		super(channel, dlog, random);	
		doConstruct(t, random);
	}
	
	/**
	 * Creates the ZK provers using sigma protocols that prove Pedersen's proofs.
	 * @param t statistical parameter
	 * @throws IOException if there was a problem in the communication
	 */
	private void doConstruct(int t, SecureRandom random) throws IOException {
		SigmaProverComputation elGamalCommittedValProver = new SigmaElGamalCommittedValueProverComputation(dlog, t, random);
		SigmaProverComputation elGamalCTKnowledgeProver = new SigmaElGamalCmtKnowledgeProverComputation(dlog, t, random);
		knowledgeProver = new  ZKPOKFromSigmaCmtPedersenProver(channel, elGamalCTKnowledgeProver);
		committedValProver = new ZKFromSigmaProver(channel, elGamalCommittedValProver);
		
	}

	@Override
	public void proveKnowledge(long id) throws IOException, CheatAttemptException, ClassNotFoundException {
		Object[] keys = getPreProcessValues();
		SigmaElGamalCmtKnowledgeProverInput input =  new SigmaElGamalCmtKnowledgeProverInput
				((ElGamalPublicKey) keys[0], ((ScElGamalPrivateKey) keys[1]).getX());
		knowledgeProver.prove(input);
	}

	@Override
	public void proveCommittedValue(long id) throws IOException, CheatAttemptException, ClassNotFoundException, CommitValueException  {
		//Send s1 to P2
		CmtElGamalCommitmentPhaseValues val = getCommitmentPhaseValues(id);
		try {
			channel.send(val.getX().generateSendableData());
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}
		SigmaElGamalCommittedValueProverInput input =  new SigmaElGamalCommittedValueProverInput(
				(ElGamalPublicKey)getPreProcessValues()[0], 
				(ElGamalCiphertextSendableData) val.getComputedCommitment().generateSendableData(), 
				(GroupElement)val.getX().getX(), val.getR().getR());
		committedValProver.prove(input);
	}
}
