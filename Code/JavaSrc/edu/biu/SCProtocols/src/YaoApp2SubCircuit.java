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
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
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
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.kdf.bc.BcKdfISO18033;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;
import edu.biu.scapi.tools.Factories.KdfFactory;


public class YaoApp2SubCircuit {

	
	/**
	 * @param args no arguments should be passed
	 */
	public static void main(String[] args) {
		
		DlogGroup dlog = null;
		KeyDerivationFunction kdf = null;
		
		
		try {
			dlog = DlogGroupFactory.getInstance().getObject("DlogECF2m(K-233)", "Miracl");
			//dlog = DlogGroupFactory.getInstance().getObject("DlogECF2m(B-233)", "Miracl");
			//dlog = DlogGroupFactory.getInstance().getObject("DlogECF2m(B-163)", "BC");
			//dlog = DlogGroupFactory.getInstance().getObject("DlogECFp(P-224)", "Miracl");
			//dlog = DlogGroupFactory.getInstance().getObject("DlogECFp(P-224)", "BC");
			//dlog = DlogGroupFactory.getInstance().getObject("DlogZpSafePrime", "CryptoPP");
			kdf = new BcKdfISO18033("SHA-1");
			
		
		} catch (FactoriesException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		Channel channel = setCommunication();	
		
		
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
	    int numberOfInputs = s.nextInt();
	    
	    inputBits = new int[numberOfInputs];
	    
	    for (int i = 0; i < numberOfInputs; i++) {
	    	
	    	//the label
	    	s.nextInt();
	    	
	    	//the input bit
	    	int input = s.nextInt();
	    	inputBits[i] = input;
	    }
		
	    Date start = new Date();
	    
	    for(int i=0; i<200;i++){
	    		
		    //create a yao's protocol
			YaoP2 yaop2 = new YaoP2(channel, dlog, kdf, inputBits,5);
			
			//run the yao's protocol as party 2
			yaop2.runWithSubCircuits();
			
			
		}
	    Date end = new Date();
		long time = (end.getTime() - start.getTime())/200;
		System.out.println("Yao's protocol party 2 took " +time + " milis");
			
	}


	/**
	 * 
	 * Loads parties from a file, sets up the channel.
	 *  
	 * @return the channel with the other party.
	 */
	private static Channel setCommunication() {
		
		List<Party> listOfParties = null;
		
		LoadParties loadParties = new LoadParties("Parties.properties");
	
		
	
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
