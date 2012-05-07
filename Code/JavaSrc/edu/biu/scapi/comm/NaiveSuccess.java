/**
 * 
 */
package edu.biu.scapi.comm;

import java.util.List;

import edu.biu.scapi.comm.EstablishedConnections;

/** 
 * @author LabTest
 */
public class NaiveSuccess implements ConnectivitySuccessVerifier {
	
	/**
	 * 
	 */
	public NaiveSuccess() {
		
	}
	
	/** 
	 * @param estCon
	 * @param originalListOfParties
	 * @return
	 */
	public boolean hasSucceded(EstablishedConnections estCon,
			List<Party> originalListOfParties) {

		//always return true
		return true;
	}
}