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

import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.CommunicationSetup;
import edu.biu.scapi.comm.ConnectivitySuccessVerifier;
import edu.biu.scapi.comm.KeyExchangeProtocol;
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
			loadParties = new LoadParties("C://work//LAST_Project//SDK//Code//JavaSrc//edu//biu//scapi//comm//Parties.properties");
			
		}



		//prepare the parties list
		listOfParties = loadParties.getPartiesList();

		//create the communication setup
		CommunicationSetup commSetup = new CommunicationSetup();

		KeyExchangeProtocol keyP = new KeyExchangeProtocol();
		ConnectivitySuccessVerifier naive = new NaiveSuccess();

		System.out.print("Before call to prepare\n");

		Collection<Channel> c = commSetup.prepareForCommunication(listOfParties, keyP, naive, 200000).values();
		Iterator<Channel> itr = c.iterator();

		//Channel ch = (Channel)((commSetup.getConnections().values()).toArray())[0];

		//Message msg = new Message();
		//byte[] data = {1,2};
		//byte[] data = new byte[1000000];

		//for(int i=0; i<1000000; i++)
		//	data[i] = 1;
		
		//msg.setData(s.getBytes());

		//String msg= "This is my message";
		
		/*
		BigInteger  msg = new BigInteger("10045663");
		System.out.println("The message is: " + msg);
		byte[] msgTobyteArr = msg.toByteArray();
		for(int i = 0 ; i < msgTobyteArr.length ; i++){
			System.out.print(msgTobyteArr[i] + ", ");
		}
		System.out.println();
		*/
		
		//Send GroupParams to other Party
		//ZpGroupParams msg = new ZpGroupParams(BigInteger.valueOf(1001), BigInteger.valueOf(2002), BigInteger.valueOf(3003));
		
		//ECF2mPentanomialBasis groupParams = new ECF2mPentanomialBasis(BigInteger.valueOf(111), BigInteger.valueOf(222), BigInteger.valueOf(333), 100, 200, 300, 400, BigInteger.valueOf(444), BigInteger.valueOf(555), BigInteger.valueOf(666));
		
		//ECF2mKoblitz msg = new ECF2mKoblitz((ECF2mGroupParams) groupParams, BigInteger.valueOf(777), BigInteger.valueOf(8));
		
		
		
		Channel channel;
		//Give each READY channel to a ReceivingThread for processing.
		while(itr.hasNext()){
			channel = itr.next();
			ReceivingThread recThread = new ReceivingThread(channel);
			recThread.start();
		}

		
		/*
		for(int i = 0; i < 1000; i++){
			if(listOfParties.get(0).getPort()==8000 && i < 10){
				
				System.out.println("About to send: " + msg);

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
				//break;
			}


		}*/

		System.out.print("End of Main\n");

	}

}
