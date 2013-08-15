/**
 * 
 */
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.equivocal;

import java.io.IOException;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZeroKnowledgeProver;
import edu.biu.scapi.securityLevel.EquivocalCT;

/**
 * Abstract implementation of Equivocal commitment scheme.
 * This is a protocol to obtain an equivocal commitment from any commitment with a ZK-protocol 
 * of the commitment value.
 * The equivocality property means that a simulator can decommit to any value it needs 
 * (needed for proofs of security).
 * 
 * This class represent the committer.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class EquivocalCTCommitter implements CTCommitter, EquivocalCT{
	
	/*
	  Runs the following pseudo code:
	  	Commit phase
			RUN any COMMIT protocol for C to commit to x
		Decommit phase, using ZK protocol of decommitment value
			SEND x to R
			Run ZK protocol as the prover, that x is the correct decommitment value
	 */
	
	protected CTCommitter cTCommitter;
	protected ZeroKnowledgeProver prover;
	private CommitValue input; //The commit value.
	private Channel channel;
	
	/**
	 * Constructor that gets channel, committer and prover to use in the protocol execution.
	 * @param channel
	 * @param cTCommitter
	 * @param prover
	 */
	public EquivocalCTCommitter(Channel channel, CTCommitter cTCommitter, ZeroKnowledgeProver prover){
		this.cTCommitter = cTCommitter;
		this.prover = prover;
		this.channel = channel;
	}
	
	/**
	 * Computes the pre process of the commitment scheme.
	 */
	public void preProcess() throws ClassNotFoundException, IOException, CheatAttemptException {
		cTCommitter.preProcess();
	}
	
	/**
	 * Runs the following line of the protocol:
	 * "RUN any COMMIT protocol for C to commit to x".
	 */
	public void commit(CommitValue input, int id) throws IOException {
		this.input = input;
		cTCommitter.commit(input, id);
	}

	/**
	 * Runs the following lines of the protocol:
	 * "SEND x to R
	 *	Run ZK protocol as the prover, that x is the correct decommitment value".
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 * @throws CheatAttemptException 
	 * @throws CommitValueException 
	 */
	public void decommit(int id) throws IOException, CheatAttemptException, ClassNotFoundException, CommitValueException {
		sendX();
		
		runZK();
	}

	/**
	 * Runs the following line of the protocol:
	 * "Run ZK protocol as the prover, that x is the correct decommitment value".
	 * @throws IOException
	 * @throws CheatAttemptException
	 * @throws ClassNotFoundException
	 * @throws CommitValueException
	 */
	protected abstract void runZK() throws IOException, CheatAttemptException, ClassNotFoundException, CommitValueException;

	/**
	 * Runs the following lines of the protocol:
	 * "SEND x to R".
	 * @throws IOException
	 */
	private void sendX() throws IOException {
		try{
			channel.send(input.generateSendableData());
		}
		catch (IOException e) {
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}
		
	}

	/**
	 * Generates CommitValue from the given byte array.
	 */
	public CommitValue generateCommitValue(byte[] x)
			throws CommitValueException {
		//delegate to the underlying committer
		return cTCommitter.generateCommitValue(x);
	}

	
	public Object getCommitment(int id) {
		// delete!
		return null;
	}
}