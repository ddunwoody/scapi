/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
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


import java.io.File;
import java.io.FileNotFoundException;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.CommunicationSetup;
import edu.biu.scapi.comm.ConnectivitySuccessVerifier;
import edu.biu.scapi.comm.KeyExchangeProtocol;
import edu.biu.scapi.comm.LoadParties;
import edu.biu.scapi.comm.NaiveSuccess;
import edu.biu.scapi.comm.Party;
import edu.biu.scapi.comm.SecurityLevel;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.kdf.bc.BcKdfISO18033;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;


/**
 * The application for yao's garbled circuit protocol for Party 2
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class YaoApp2WithThreads {

	
	/**
	 * 
	 * 
	 * @param args no arguments should be passed
	 */
	public static void main(String[] args)  {
		
		DlogGroup dlog = null;
		KeyDerivationFunction kdf = null;
		
		try {
			//use the koblitz curve via miracl
			dlog = DlogGroupFactory.getInstance().getObject("DlogECF2m(K-233)", "Miracl");
			//dlog = DlogGroupFactory.getInstance().getObject("DlogECF2m(B-233)", "Miracl");
			// dlog = DlogGroupFactory.getInstance().getObject("DlogECFp(P-224)", "Miracl");
			kdf = new BcKdfISO18033("SHA-1");
			
		
		} catch (FactoriesException e1) {
			e1.printStackTrace();
		}
		
		//set up the communication with the other side and get the created channel
		Channel channel = setCommunication("Parties.properties");
		
		//set up another channel for the OT thread
		Channel channelOT = setCommunication("PartiesOT.properties");
		
		
					
		//get the input from a file
		File f = new File("AESPartyTwoInputs.txt");
		int[] inputBits = null;
		
		//get input from a file
		Scanner s = null;
		try {
			s = new Scanner(f);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//get the input bits
	    int numberOfInputs = s.nextInt();
	    
	    inputBits = new int[numberOfInputs];
	    
	    //take bit by bit from the file using the scanner
	    for (int i = 0; i < numberOfInputs; i++) {
	    	
	    	//the label
	    	s.nextInt();
	    	
	    	//the input bit
	    	int input = s.nextInt();
	    	inputBits[i] = input;
	    }
		
	    Date start = new Date();
	    
	    //run the yao protocol multiple times
	    for(int i=0; i<100;i++){
	    	
	    //create a yao's protocol
		YaoP2 yaop2 = new YaoP2(channel, dlog, kdf, inputBits);
		
		//run the yao's protocol as party 2
		yaop2.run();
		
	    }
		
		Date end = new Date();
		long time = (end.getTime() - start.getTime())/100;
		System.out.println("Yao's protocol party 2 took " +time + " milis");
		
			
	}


	/**
	 * 
	 * Loads parties from a file, sets up the channel.
	 *  
	 * @return the channel with the other party.
	 */
	private static Channel setCommunication(String fileName) {
		
		List<Party> listOfParties = null;
		
		LoadParties loadParties = new LoadParties(fileName);
	
		
	
		//prepare the parties list
		listOfParties = loadParties.getPartiesList();
	
		//create the communication setup
		CommunicationSetup commSetup = new CommunicationSetup();
	
		KeyExchangeProtocol keyP = new KeyExchangeProtocol();
		ConnectivitySuccessVerifier naive = new NaiveSuccess();
	
		System.out.print("Before call to prepare\n");
		
		commSetup.prepareForCommunication(listOfParties, keyP, SecurityLevel.PLAIN, naive, 200000);
			
		//return the channel with the other party. There was only one channel created
		return (Channel)((commSetup.getConnections().values()).toArray())[0];
	}

}
