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
 * File: ApplicationTest.java.
 * Creation date Feb 20, 2011
 * Created by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.comm.test;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.CommunicationSetup;
import edu.biu.scapi.comm.ConnectivitySuccessVerifier;
import edu.biu.scapi.comm.KeyExchangeProtocol;
import edu.biu.scapi.comm.Message;
import edu.biu.scapi.comm.NaiveSuccess;
import edu.biu.scapi.comm.Party;
import edu.biu.scapi.comm.SecurityLevel;

/**
 * @author LabTest
 *
 */
public class ApplicationTest {

	/**
	 * main
	 * @param args
	 */
	public static void main(String[] args) {

		
		System.out.print("Start main\n");
		List<Party> listOfParties;
		LoadParties loadParties;
		
		if (args.length > 0){
			
			loadParties = new LoadParties(args[0]);
		}
		else{
			//load the parties
			loadParties = new LoadParties("Parties.properties");
		
		}
			
		
		
		//prepare the parties list
		listOfParties = loadParties.getPartiesList();
		
		//create the communication setup
		CommunicationSetup commSetup = new CommunicationSetup();
		
		KeyExchangeProtocol keyP = new KeyExchangeProtocol();
		ConnectivitySuccessVerifier naive = new NaiveSuccess();
		
		System.out.print("Before call to prepare\n");
		
		commSetup.prepareForCommunication(listOfParties, keyP, SecurityLevel.SECURE, naive, 200000);
		
		//Channel ch = (Channel)((commSetup.getConnections().values()).toArray())[0];
		
		Message msg = new Message();
		//byte[] data = {1,2};
		byte[] data = new byte[1000000];
		
		for(int i=0; i<1000000; i++)
			data[i] = 1;
		msg.setData(data);
		
		
		while(true){
			
			if(listOfParties.get(0).getPort()==8000){
				
					
					//set an iterator for the connection map.
					Collection<Channel> c = commSetup.getConnections().values();
					Iterator<Channel> itr = c.iterator();
					
					Channel channel;
					//go over the map and check if all the connections are in READY state
					while(itr.hasNext()){
						channel = itr.next();
					    try {
							channel.send(msg);
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					       }
			}

			else{
			
				
					//set an iterator for the connection map.
					Collection<Channel> c = commSetup.getConnections().values();
					Iterator<Channel> itr = c.iterator();
					
					Channel channel;
					//go over the map and check if all the connections are in READY state
					while(itr.hasNext()){
						channel = itr.next();
					    ReceivingThread recThread = new ReceivingThread(channel);
						recThread.start();
					       }
					break;
					}
			
				
		}
		
		//System.out.print("End of Main\n");
		
	}

}
