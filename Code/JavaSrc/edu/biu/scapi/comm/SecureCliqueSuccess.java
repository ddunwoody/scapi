/**
 * 
 */
package edu.biu.scapi.comm;

import java.util.List;

import edu.biu.scapi.comm.EstablishedConnections;

/** 
 * <!-- begin-UML-doc -->
 * <!-- end-UML-doc -->
 * @author LabTest
 * @generated "UML to Java (com.ibm.xtools.transform.uml2.java5.internal.UML2JavaTransform)"
 */
public class SecureCliqueSuccess implements ConnectivitySuccessVerifier {

	/**
	 * 
	 */
	public SecureCliqueSuccess() {
		
	}

	/** 
	 * •	Check if connected to all parties in original list.
	 * •	Ask every party if they are connected to all parties in their list. USE SECURE BROADCAST. DO NOT TRUST THE OTHER PARTIES.
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
		
		return false;
		
	}
}