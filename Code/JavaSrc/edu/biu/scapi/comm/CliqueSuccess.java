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
 * 
 */
package edu.biu.scapi.comm;

import java.util.List;

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
