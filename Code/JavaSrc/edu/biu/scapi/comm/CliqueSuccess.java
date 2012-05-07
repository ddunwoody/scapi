/**
 * 
 */
package edu.biu.scapi.comm;

import java.util.List;

import edu.biu.scapi.comm.EstablishedConnections;

/** 
 * @author LabTest
 */
public class CliqueSuccess implements ConnectivitySuccessVerifier {
	
	/**
	 * 
	 */
	public CliqueSuccess() {
		
	}
	
	/** 
	 * 
	 * •	Check if connected to all parties in original list.
	 * •	Ask every party if they are connected to all parties in their list.
	 * •	If all answers are true, return true,
	 * •	Else, return false.
	 * 
	 * @param estCon the EstablishedConnections object that includes the actual connections formed
	 * @param originalListOfParties the original list of parties
	 * 
	 * 
	 */
	public boolean hasSucceded(EstablishedConnections estCon,
			List<Party> originalListOfParties) {
		// begin-user-code
		// TODO Auto-generated method stub
		return false;
		// end-user-code
	}
}