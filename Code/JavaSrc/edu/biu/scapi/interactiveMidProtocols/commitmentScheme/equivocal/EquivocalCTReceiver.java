/**
 * 
 */
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.equivocal;

import java.io.IOException;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.ReceiverCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZeroKnowledgeVerifier;
import edu.biu.scapi.securityLevel.EquivocalCT;

/**
 * Abstract implementation of Equivocal commitment scheme.
 * This is a protocol to obtain an equivocal commitment from any commitment with a ZK-protocol 
 * of the commitment value.
 * The equivocality property means that a simulator can decommit to any value it needs 
 * (needed for proofs of security).
 * 
 * This class represent the receiver.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class EquivocalCTReceiver implements CTReceiver, EquivocalCT {
	
	/*
	  Runs the following pseudo code:
	  	Commit phase
			RUN any COMMIT protocol for C to commit to x
		Decommit phase, using ZK protocol of decommitment value
			Run ZK protocol as the verifier, that x is the correct decommitment value
			IF verifier-output of ZK is ACC
		          OUTPUT ACC and x
		    ELSE
		          OUTPUT REJ

	 */
	
	protected CTReceiver cTReceiver;
	protected ZeroKnowledgeVerifier verifier;
	protected Channel channel;
	
	/**
	 * Constructor that gets channel, receiver and verifier to use in the protocol execution.
	 * @param channel
	 * @param cTCommitter
	 * @param prover
	 */
	public EquivocalCTReceiver(Channel channel, CTReceiver cTReceiver, ZeroKnowledgeVerifier verifier){
		this.cTReceiver = cTReceiver;
		this.verifier = verifier;
		this.channel = channel;
	}
	
	/**
	 * Computes the pre process of the commitment scheme.
	 */
	public void preProcess() throws IOException {
		cTReceiver.preProcess();
	}

	/**
	 * Runs the following line of the protocol:
	 * "RUN any COMMIT protocol for C to commit to x".
	 */
	public ReceiverCommitPhaseOutput receiveCommitment() throws ClassNotFoundException, IOException {
		return cTReceiver.receiveCommitment();
	}

	/**
	 * Runs the following lines of the protocol:
	 * "Run ZK protocol as the verifier, that x is the correct decommitment value
	 *		IF verifier-output of ZK is ACC
	 *          OUTPUT ACC and x
	 *    	ELSE
	 *          OUTPUT REJ".
	 */
	public CommitValue receiveDecommitment(int id) throws ClassNotFoundException, IOException, CommitValueException, CheatAttemptException{
		CommitValue x = waitForMsgFromCommitter();
		
		runZK(x);
		
		return x;
	}

	/**
	 * Runs the underlying ZK protocol.
	 * @param x
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws CommitValueException
	 * @throws CheatAttemptException
	 */
	protected abstract void runZK(CommitValue x) throws IOException, ClassNotFoundException, CommitValueException, CheatAttemptException;

	/**
	 * receives the message from the committer.
	 * @return
	 * @throws ClassNotFoundException
	 * @throws IOException
	 */
	protected abstract CommitValue waitForMsgFromCommitter() throws ClassNotFoundException, IOException;

	
}