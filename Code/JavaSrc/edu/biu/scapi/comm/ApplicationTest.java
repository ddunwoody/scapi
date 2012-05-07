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
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			else{
			
				try {
					ch.receive();
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
