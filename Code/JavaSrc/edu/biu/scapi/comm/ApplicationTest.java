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
package edu.biu.scapi.comm;

import java.io.IOException;
import java.util.List;

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
		
		commSetup.prepareForCommunication(listOfParties, keyP, SecurityLevel.AUTHENTICATED, naive, 100000);
		
		Channel ch = (Channel)((commSetup.getConnections().values()).toArray())[0];
		
		Message msg = new Message();
		byte[] data = {1,2};
		msg.setData(data);
		
		
		while(true){
			
			if(listOfParties.get(0).getPort()==8001){
				try {
					ch.send(msg);
					System.out.println("Sent msg1: " + msg);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			else{
			
				try {
					ch.receive();
					System.out.println("Received msg2: " + msg);
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		
		//System.out.print("End of Main\n");
		
	}

}
