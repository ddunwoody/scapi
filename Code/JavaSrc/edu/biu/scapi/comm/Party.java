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
 * 
 * The Party class has information such as the IP address and port to connect to or listen. 
 * Since the Party is built by the outside application, the IP and port will be given as two separate items. 
 * When the CommunicationSetup gets the list of parties and prepares the data structure EstablishedConnections it converts 
 * the two items into an InetSocketAddress, which will serve as the key to the map where all channels are saved. 
 * The IP and port define a unique party and it is assumed that every party gets the same list of participating parties 
 * from the respective calling applications. If the application wants to keep a serial id number for each party it can do so, 
 * but from the CommunicationSetup perspective the id is the combination of the IP address and port. 
 * 
 */
package edu.biu.scapi.comm;

import java.net.InetAddress;
import java.security.Key;

/** 
 * @author LabTest
 */
public class Party {
	private final String name;
	private final InetAddress ipAddress;
	private final Key key;
	private final int port;
	private final Role role;
	
	/**
	 * A constructor which sets all the data of a Party. Since all the fields are final once they are set they can not be changed.
	 * @param name
	 * @param ipAdress
	 * @param key
	 * @param port
	 * @param role
	 */
	public Party(String name, InetAddress ipAdress, Key key, int port, Role role){
		
		this.name = name;
		this.ipAddress = ipAdress;
		this.key = key;
		this.port = port;
		this.role = role;
		
	}
	/**
	 * 
	 * Compares the ip and port represented as strings between two parties.
	 * @param otherParty the other party to compare to
	 * @return 0 if the two parties are equal 
	 * 		   <0 if this party's string is smaller than the otherParty string.
	 * 		   >0 if this party's string is larger than the otherParty string.
	 */
	public int compareTo(Party otherParty){
		
		//first create the two strings of the two parties
		String thisString = ipAddress.toString() + ":" + port;
		String otherString = otherParty.getIpAddress().toString() + ":" + otherParty.getPort();
		int ret = thisString.compareTo(otherString);
		return ret;
		
	}


	/**
	 * @return the ipAddress
	 */
	public InetAddress getIpAddress() {
		return ipAddress;
	}


	/**
	 * @return the port
	 */
	public int getPort() {
		return port;
	}
}
