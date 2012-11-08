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


package edu.biu.scapi.comm.test;



import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.CommunicationSetup;
import edu.biu.scapi.comm.ConnectivitySuccessVerifier;
import edu.biu.scapi.comm.KeyExchangeProtocol;
import edu.biu.scapi.comm.NaiveSuccess;
import edu.biu.scapi.comm.Party;
import edu.biu.scapi.comm.SecurityLevel;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.CramerShoupDDHEnc;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScCramerShoupDDHOnGroupElement;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScCramerShoupPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScCramerShoupPublicKey;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.GroupElementPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.ZpSafePrimeElementCryptoPp;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mKoblitz;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mPentanomialBasis;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.tests.midLayer.cramerShoup.CramerShoupTestConfig;
import edu.biu.scapi.tools.Factories.CryptographicHashFactory;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

public class CramerShoupWithCommTest {
	/*
	 This is an application that does the following:
		
 		a.       For 3 different curves (1 over a prime field, one over a GF field and one Koblitz curve; all of sizes about 200) 
 				 and with Zp (with a 1024 bit prime and a 2048 bit prime), and with SHA1 for the elliptic curve instantiations and SHA256 with the Zp instantiations:

                   i.      Initializes Cramer Shoup
 
                   ii.      Generates a group element

                   iii.      Encrypts 1000 times; output average encryption time (saying which instantiation)

                   iv.      Decrypts 1000 times; output average decryption time (saying which instantiation)

	 */
	
	private static final String FILES_PATH = System.getProperty("user.dir") + "/javaSrc/edu/biu/scapi/tests/midLayer/cramerShoup/";
	
	
	static public Map<InetSocketAddress, Channel> prepareCommunication(String[] args){
		System.out.println("Prepare communcation");
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

		return commSetup.prepareForCommunication(listOfParties, keyP, SecurityLevel.PLAIN, naive, 200000);

	}
	
	
	
	static public String runTest(CramerShoupTestConfig config, Channel channel) throws FactoriesException{
		DlogGroup dlogGroup;
		//Create the requested Dlog Group object. Do this via the factory.
		if(config.getDlogProvider() != null){
			dlogGroup = DlogGroupFactory.getInstance().getObject(config.getDlogGroup()+"("+config.getAlgorithmParameterSpec()+")", config.getDlogProvider());
		}else {
			config.setDlogProvider("Default");
			dlogGroup = DlogGroupFactory.getInstance().getObject(config.getDlogGroup()+"("+config.getAlgorithmParameterSpec()+")");
		}
		
		System.out.println("Sending Dlog Group params");
		try {
			channel.send(dlogGroup.getGroupParams());
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		CryptographicHash hash;
		//Create the requested hash. Do this via the factory.
		if(config.getHashProvider() != null){
			hash = CryptographicHashFactory.getInstance().getObject(config.getHash(), config.getHashProvider());
		}else {
			config.setHashProvider("Default");
			hash = CryptographicHashFactory.getInstance().getObject(config.getHash());
		}
		
		System.out.println("Sending hash alg name");
		try {
			channel.send(hash.getAlgorithmName());
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		//Create a random group element. This element will be encrypted several times as specified in config file and decrypted several times
		//as specified in config. 
		//Measure and output the average running time for encrypting and the average running time for decrypting.
		//Sanity check that that the decrypted element equals the original element.
		GroupElement gEl = dlogGroup.createRandomElement();
		System.out.println("Sending group element: " + gEl);
		try {
			channel.send(gEl.generateSendableData());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		
		//Create a Cramer Shoup Encryption/Decryption object. Do this directly by calling the relevant constructor. (Can be done instead via the factory).
		ScCramerShoupDDHOnGroupElement enc = new ScCramerShoupDDHOnGroupElement(dlogGroup, hash);
		
		System.out.println("Sending encryption scheme's name");
		try {
			channel.send(enc.getAlgorithmName());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		//Generate and set a suitable key.
		KeyPair keyPair = enc.generateKey();
		//System.out.println("Sending the encryption schemes public key: " + keyPair.getPublic());
		System.out.println("Sending the encryption schemes private key: " + keyPair.getPrivate());
		
		try {
			channel.send(((ScCramerShoupPublicKey)keyPair.getPublic()).generateSendableData());
			channel.send(((ScCramerShoupPrivateKey)keyPair.getPrivate()).generateSendableData());
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		
		try {
			enc.setKey(keyPair.getPublic(),keyPair.getPrivate());
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}

		//Wrap the group element we want to encrypt with a Plaintext object.
		Plaintext plainText = new GroupElementPlaintext(gEl);
		System.out.println("Sending the GroupElementPlaintext: " + gEl);
		
		try {
			channel.send(plainText.generateSendableData());
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		
		AsymmetricCiphertext cipher = null;
		
		//Measure the time it takes to encrypt each time. Calculate and output the average running time.
		//Calendar cal = Calendar.getInstance();
		long allTimes = 0;
		
		long start = System.currentTimeMillis();
		long stop = 0;
		long duration = 0;
		
		int encTestTimes = new Integer(config.getNumTimesToEnc()).intValue();
		for(int i = 0; i < encTestTimes; i++){
			cipher = enc.encrypt(plainText);
			stop = System.currentTimeMillis();
			duration = stop - start;
			//System.out.println("One time encrypting time in ms is: " + duration);
			start = stop;
			allTimes += duration;
		}
		double encAvgTime = (double)allTimes/(double)encTestTimes;
		
		System.out.println("Sending the cipher: " + cipher);
		
		try {
			channel.send(cipher.generateSendableData());
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		GroupElementPlaintext decrypted = null;
		allTimes = 0;
		int decTestTimes = new Integer(config.getNumTimesToDec()).intValue();
		//Measure the time it takes to decrypt each time. Calculate and output the average running time.
		for(int i = 0; i < decTestTimes; i++){
			try {
				decrypted = (GroupElementPlaintext) enc.decrypt(cipher);
				stop = System.currentTimeMillis();
				duration = stop - start;
				start = stop;
				allTimes += duration;
			} catch (KeyException e) {
				e.printStackTrace();
			}
		}
		
		System.out.println("Sending the decrypted msg: " + decrypted);

		try {
			channel.send(decrypted.generateSendableData());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		boolean equal = gEl.equals(decrypted.getElement());
		double decAvgTime = (double)allTimes/(double)decTestTimes;
		//Prepare an output string (csv format)
		String result = config.getDlogGroup() + "," + config.getDlogProvider() + "," + config.getAlgorithmParameterSpec() + "," + config.getHash() + "," + config.getHashProvider() + "," + config.getNumTimesToEnc();
		result += "," + encAvgTime + "," + config.getNumTimesToDec() + "," + decAvgTime + "," + equal;
				
		System.out.println("Going to sleep for 10 seconds");
		try {
			Thread.sleep(10000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;
	}
	
	static public String runPerformanceOfSerializationTest(CramerShoupTestConfig config, Channel channel) throws FactoriesException{
		DlogGroup dlogGroup;
		String result;
		//Create the requested Dlog Group object. Do this via the factory.
		if(config.getDlogProvider() != null){
			dlogGroup = DlogGroupFactory.getInstance().getObject(config.getDlogGroup()+"("+config.getAlgorithmParameterSpec()+")", config.getDlogProvider());
		}else {
			config.setDlogProvider("Default");
			dlogGroup = DlogGroupFactory.getInstance().getObject(config.getDlogGroup()+"("+config.getAlgorithmParameterSpec()+")");
		}
		System.out.println("The Dlog group is: " + dlogGroup.getGroupType() + " Provider: " + config.getDlogProvider());

		System.out.println("Sending Dlog Group params" + dlogGroup.getGroupParams());
		try {
			channel.send(dlogGroup.getGroupParams());
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		//Create a random group element. This element will be sent to the other side several times. 
		//Measure the time it takes to send each time. Calculate and output the average running time.

		long allTimes = 0;	
		long start = System.currentTimeMillis();
		long stop = 0;
		long duration = 0;
		
		int runTestTimes = new Integer(config.getNumTimesToEnc()).intValue();
		double encAvgTime;
		
		try {
			channel.send("New random element");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		for(int i = 0; i < runTestTimes; i++){
			GroupElement gEl = dlogGroup.createRandomElement();
			//System.out.println("Sending group element: " + gEl);
			try {
				channel.send(gEl.generateSendableData());
				stop = System.currentTimeMillis();
				duration = stop - start;
				//System.out.println("One time encrypting time in ms is: " + duration);
				start = stop;
				allTimes += duration;
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			if(i == runTestTimes -1){
				System.out.println("The last group element sent is: " + gEl);
				System.out.println("Its sendable data is: " + gEl.generateSendableData());
			}
			
		}
		encAvgTime = (double)allTimes/(double)runTestTimes;
		
		result = "The average time of sending a new random group element " + runTestTimes + " times is: " + encAvgTime;
		System.out.println(result);
		
		try {
			channel.send("End of communication");
		} catch (IOException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		
		
		
		/*
		GroupElement gEl = dlogGroup.createRandomElement();
		try {
			channel.send("Same random element");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		for(int i = 0; i < runTestTimes; i++){
			System.out.println("Sending group element: " + gEl);
			try {
				channel.send(gEl.generateSendableData());
				stop = System.currentTimeMillis();
				duration = stop - start;
				//System.out.println("One time encrypting time in ms is: " + duration);
				start = stop;
				allTimes += duration;
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
		encAvgTime = (double)allTimes/(double)runTestTimes;
		
		result = "The average time of sending the same random group element " + runTestTimes + " times is: " + encAvgTime;
		System.out.println(result);
		try {
			channel.send("End of communication");
		} catch (IOException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		
				
		try {
			channel.send("Values of random element");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		for(int i = 0; i < runTestTimes; i++){
			GroupElement gEl1 = dlogGroup.createRandomElement();
			System.out.println("Sending values of group element: " + gEl1);
			BigInteger grElValues[] = new BigInteger[2];
			if(gEl1 instanceof ZpSafePrimeElementCryptoPp){
				grElValues[0] = ((ZpSafePrimeElementCryptoPp)gEl1).getElementValue();
			}else {
				grElValues[0] = ((ECElement)gEl1).getX();
				grElValues[1] = ((ECElement)gEl1).getY();
			}
			try {
				channel.send(grElValues[0]);
				if(grElValues[1] != null)
					channel.send(grElValues[1]);
				stop = System.currentTimeMillis();
				duration = stop - start;
				//System.out.println("One time encrypting time in ms is: " + duration);
				start = stop;
				allTimes += duration;
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
		encAvgTime = (double)allTimes/(double)runTestTimes;
		
		result = "The average time of sending the values of a random group element " + runTestTimes + " times is: " + encAvgTime;
		System.out.println(result);
		try {
			channel.send("End of communication");
		} catch (IOException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		
		
		*/
		
		System.out.println("Going to sleep for 300 seconds");
		try {
			Thread.sleep(300000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return result;
	}
	
	static CramerShoupTestConfig[] readConfigFile() {
		CramerShoupTestConfig[] configArray = null;
		try {
			BufferedReader bf = new BufferedReader(new FileReader(FILES_PATH + "CramerShoupTestConfig.ini"));
			String line;
			String[] tokens;
			line = bf.readLine();
			int numOfTests = 0;
			if (line.startsWith("NumOfTests")) {
				tokens = line.split("=");
				String tok = tokens[1].trim();
				numOfTests = new Integer(tok).intValue();
			}
			configArray = new CramerShoupTestConfig[numOfTests];
			int i = 0;
			String dlogGroup = null;
			String dlogProvider = null;
			String algorithmParameterSpec = null;
			String hash = null;
			String hashProvider = null;
			String numTimesToEnc = null;
			String numTimesToDec = null;

			int count = 0;
			while ((line = bf.readLine()) != null) {
				// System.out.println(line);
				if (line.startsWith("dlogGroup")) {
					tokens = line.split("=");
					dlogGroup = tokens[1].trim();
				} else if (line.startsWith("dlogProvider")) {
					tokens = line.split("=");
					if(tokens.length > 1){
						dlogProvider = tokens[1].trim();
					}
				} else if (line.startsWith("algorithmParameterSpec")) {
					tokens = line.split("=");
					algorithmParameterSpec = tokens[1].trim();
				} else if (line.startsWith("hash")) {
					tokens = line.split("=");
					hash = tokens[1].trim();
				} else if (line.startsWith("providerHash")) {
					tokens = line.split("=");
					if(tokens.length > 1){
						hashProvider = tokens[1].trim();
					}
				} else if (line.startsWith("numTimesToEnc")) {
					tokens = line.split("=");
					numTimesToEnc = tokens[1].trim();
				} else if (line.startsWith("numTimesToDec")) {
					tokens = line.split("=");
					numTimesToDec = tokens[1].trim();
				}
				
				count++;
				if (count == 7) {
					configArray[i] = new CramerShoupTestConfig(dlogGroup, dlogProvider, algorithmParameterSpec, hash, hashProvider, numTimesToEnc, numTimesToDec); 
															
					i++;
					count = 0;
				}
			}

			bf.close();
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
		return configArray;

	}


	
	
	/**
	 * This program tests the average running times of encrypting and decrypting a Group Element with the Cramer Shoup encryption scheme. 
	 * It reads a set a tests from a config files, runs them and prints the results. The set of tests contains information about the Dlog Group to use, 
	 * the Hash function to use (it is possible to choose the providers for them).  
	 * @param args
	 * @throws FactoriesException 
	 */
	public static void main(String[] args) throws FactoriesException {
		try {

			// Get parameters from config file:
			CramerShoupTestConfig[] config = readConfigFile();
			DateFormat dateFormat = new SimpleDateFormat("dd_MM_yyyy_HH_mm_ss");
			Date date = new Date();
			String testName = FILES_PATH + "CramerShoupTestResults_" + dateFormat.format(date) + ".csv";
			PrintWriter out = new PrintWriter(testName);
			out.println("Dlog Group,Dlog Provider,Dlog Parameter,Hash,Hash Provider,Number of Times Encrypting, Average Encrypting Time (ms),Number of Times Decrypting,Average Decrypting Time (ms),Decrypted Element Equals Plaintext");
			out.flush();
			String result = null;
			
			Map<InetSocketAddress, Channel> map = prepareCommunication(args);
			//set an iterator for the connection map.
			Collection<Channel> c = map.values();
			Iterator<Channel> itr = c.iterator();

			Channel channel;
			//Get the first channel available
			channel = itr.next();
			
			for (int i = 0; i < config.length; i++) {
				//result = runTest(config[i], channel);
				//out.println(result);
				//System.out.println(result);
				result = runPerformanceOfSerializationTest(config[i], channel);
				out.println(result);
			}
			out.flush();
			out.close();
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (IOException e) {
				e.printStackTrace();
		} catch (FactoriesException e) {
			e.printStackTrace();
		}
	}

}
