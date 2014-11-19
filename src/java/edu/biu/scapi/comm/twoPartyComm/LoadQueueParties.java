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

package edu.biu.scapi.comm.twoPartyComm;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

/**
 * Utility class for reading a list of queue parties from a file. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class LoadQueueParties {
	
	private Properties parties;
	List<PartyData> listOfParties;
	String url;
	
	/**
	 * Constructor that get the name of the file and create the properties object using it.
	 * @param nameOfFile the file to read from.
	 */
	public LoadQueueParties(String nameOfFile){
		
		//Create the properties and get the config file.
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
        
        //Create the list to hold all parties.
        listOfParties = new LinkedList<PartyData>();
  		QueuePartyData party;
  		int id;
  		
  		//Go over the properties to retrieve all the parties.
  		//Get the total number of parties.
  		url = parties.getProperty("URL");
  		
  		//Get the total number of parties.
  		int numOfParties = Integer.parseInt(parties.getProperty("NumOfParties"));
  		
  		//Create each party with the url, id and number of connections.
  		//put the created party in the list.
  		for(int i=0; i<numOfParties;i++)
  		{
  			id = Integer.parseInt(parties.getProperty("ID" + i));
  			party = new QueuePartyData(id);
  			
  			listOfParties.add(party);
  		}
        
	}
	
	/**
	 * Read the parties from the file and return a list of the parties.
	 */
	public List<PartyData> getPartiesList(){
		//Return the list filled with parties.
  		return listOfParties;
	}
	
	public String getURL(){
		return url;
	}
}
