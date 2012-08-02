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
 * Project: scapi.
 * Package: edu.biu.scapi.comm.
 * File: LoadParties.java.
 * Creation date Feb 20, 2011
 * Created by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.comm;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

/**
 * @author LabTest
 *
 */
public class LoadParties {
	
	private Properties parties; 
	
	
	LoadParties(String nameOfFile){
		
		//create the properties and get the config file
        parties = new Properties();
        
        try {
        	
        	parties.load(new FileInputStream(nameOfFile));
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        
	}
	
	/**
	 * 
	 * @return
	 */
	List<Party> getPartiesList(){
		
		List<Party> listOfParties = new LinkedList<Party>();
		Party party;
		InetAddress ip = null;
		int port = 0;
		
		//go over the properties to retrieve all the parties
		
		//get the total number of parties
		int numOfParties = Integer.parseInt(parties.getProperty("NumOfParties"));
		
		for(int i=0; i<numOfParties;i++)
		{
			try {
				ip = InetAddress.getLocalHost();
				ip = InetAddress.getByName(parties.getProperty("IP" + i));
				port = Integer.parseInt(parties.getProperty("Port" + i));
			} catch (UnknownHostException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			party = new Party("", ip, null, port, null);
			
			listOfParties.add(party);
		}
		
		
		
		return listOfParties;
	}
}
