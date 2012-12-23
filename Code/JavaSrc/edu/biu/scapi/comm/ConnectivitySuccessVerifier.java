/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
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
