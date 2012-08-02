/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
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
