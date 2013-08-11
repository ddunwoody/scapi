/**
 * 
 */
package edu.biu.scapi.interactiveMidProtocols.committmentScheme;

import java.io.IOException;

public interface CTReceiver {
	public void preProcess() throws IOException;


	public ReceiverCommitPhaseOutput receiveCommitment() throws ClassNotFoundException, IOException;

	public CommitValue receiveDecommitment(int id) throws ClassNotFoundException, IOException;
	
}