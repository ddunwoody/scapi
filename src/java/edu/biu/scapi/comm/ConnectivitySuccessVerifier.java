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

package edu.biu.scapi.comm;

import java.util.List;

/** 
 * Different Multi-parties computations  may require different types of success when checking the connections between all the parties that were supposed to participate.
 * Some protocols may need to make sure that absolutely all parties participating in it have established connections one with another; other protocols may need only a certain percentage
 * of connections to have succeeded. There are many possibilities and each one of them is represented by a class implementing this interface. The different classes that 
 * implement this interface will run different algorithms to verify the level of success of the connections. It is up to the user of the CommunicationSetup
 * to choose the relevant level and pass it on to the CommunicationSetup upon calling the prepareForCommuncation function.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface ConnectivitySuccessVerifier {

	/**
	 * This function gets the information about the established connections as input and the original list of parties, then it runs a certain algorithm 
	 * (determined by the implementing class), and it returns true or false according to the level of connectivity checked by the implementing algorithm.
	 *  
 	 * @param estCon the actual established connections
	 * @param originalListOfParties the original list of parties to connect to
	 * @return true if the level of connectivity was reached (depends on implementing algorithm) and false otherwise.
	 */
	public boolean hasSucceded(EstablishedConnections estCon, List<Party> originalListOfParties);
	
}
