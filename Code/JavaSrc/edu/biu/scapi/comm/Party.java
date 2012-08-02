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
		
		System.out.println(thisString);
		String otherString = otherParty.getIpAddress().toString() + ":" + otherParty.getPort();
		System.out.println(otherString);
		
		
		
		int ret = thisString.compareTo(otherString);
		
		System.out.println(ret);
		
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
