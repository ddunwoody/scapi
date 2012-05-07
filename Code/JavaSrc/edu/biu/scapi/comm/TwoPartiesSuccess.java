/**
 * 
 */
package edu.biu.scapi.comm;

import java.util.List;

import edu.biu.scapi.comm.EstablishedConnections;

/** 
* @author LabTest
 */
public class TwoPartiesSuccess implements ConnectivitySuccessVerifier {
	
	/**
	 * 
	 */
	public TwoPartiesSuccess() {
		
	}
	
	/** 
	 * @param estCon
	 * @param originalListOfParties
	 * @return
	 */
	public boolean hasSucceded(EstablishedConnections estCon,
			List<Party> originalListOfParties) {
		return false;
		
	}
}