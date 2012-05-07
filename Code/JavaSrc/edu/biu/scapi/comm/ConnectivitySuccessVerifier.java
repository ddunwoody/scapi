/**
 * Different MPCs may require different types of success when checking the connections between all the parties that were supposed to participate.
 * The application running the protocol will ask the protocol which type it needs, and will pass the CommunicationSetup an instance of 
 * ConnectivitySuccessVerifier that responds to the required type. We use here the Strategy Pattern to allow us to change the algorithm accordingly.
 * In all cases 
 * 	• the verifier will get the information about the established connections as input and the original list of parties, 
 * 	• it will run a certain algorithm,
 * 	• it will return true or false. 
 */
package edu.biu.scapi.comm;

import java.util.List;

import edu.biu.scapi.comm.EstablishedConnections;

/** 
 * @author LabTest
 */
public interface ConnectivitySuccessVerifier {

	/** 
	 * @param estCon this object includes the map of connections. These connections are the actual connections that were created. 
	 *                 The decision if the success is true or false will be based on the actual connections compared to the original list of parties 
	 *                 and possibly concrete connections of other parties (in that case the information will be sent to us by the other parties)
	 * @param originalListOfParties the original list of parties to connect to
	 * @return true if the connections are satisfiable and false otherwise.
	 */
	public boolean hasSucceded(EstablishedConnections estCon, List<Party> originalListOfParties);
	
}