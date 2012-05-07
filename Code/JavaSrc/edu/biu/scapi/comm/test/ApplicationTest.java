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
