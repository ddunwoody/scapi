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

package edu.biu.scapi.comm.twoPartyComm;

import java.net.InetAddress;

/**
 * This class holds the data of a party in a communication layer. 
 * It should be used in case the user wants to use the regular mechanism of communication using tcp sockets.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SocketPartyData implements PartyData{
	
	private final InetAddress ipAddress;	//Party's address.
	private final int port;					//Port number to listen on.
	
	/**
	 * Constructor that sets the given arguments.
	 * @param ip Party's address.
	 * @param port Port number to listen on.
	 */
	public SocketPartyData(InetAddress ip, int port){
		this.ipAddress = ip;
		this.port = port;
		
	}
	
	public InetAddress getIpAddress() {
		return ipAddress;
	}
	
	public int getPort() {
		return port;
	}
	
	/**
	 * Compares two parties.
	 * @param otherParty the other party to compare to.
	 * @return 0 if the two parties are equal .
	 * 		   <0 if this party's string is smaller than the otherParty's string representation.
	 * 		   >0 if this party's string is larger than the otherParty's string representation.
	 */
	public int compareTo(SocketPartyData otherParty){
		
		//first create the two strings of the two parties
		String thisString = ipAddress.toString() + ":" + port;
		String otherString = otherParty.getIpAddress().toString() + ":" + otherParty.getPort();
		int ret = thisString.compareTo(otherString);
		return ret;
		
	}

}
