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
 * Key Exchange Protocols are implemented using the Strategy design pattern so that different protocols can be chosen by the application. 
 * An instance of the chosen concrete class is passed to the CommunicationSetup. We will currently implement three options:
 *   •	Init key, in this protocol each party has already received as input the shared keys.
 *   •	Plain Diffie-Hellman Key Exchange.
 *   •	Universally Composable Diffie-Hellman.
 * Since Key Exchange Protocols are a type of Protocol, they also implement the Protocol Interface. 
 */
package edu.biu.scapi.comm;


/** 
* @author LabTest
 */
public class KeyExchangeProtocol implements Protocol{

	
	/**
	 * 
	 */
	public KeyExchangeProtocol() {
		
	}
	
	/**
	 * 
	 */
	public ProtocolOutput getOutput() {

		return new KeyExchangeOutput();
	}

	/**
	 * 
	 */
	public void run() {
		// TODO Auto-generated method stub
		
	}

	/**
	 * 
	 */
	public void start(ProtocolInput protocolInput) {
		// TODO Auto-generated method stub
		
	}
}
