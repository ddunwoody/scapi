import java.io.File;
import java.io.FileNotFoundException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.encryption.AESFixedKeyMultiKeyEncryption;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.CommunicationSetup;
import edu.biu.scapi.comm.ConnectivitySuccessVerifier;
import edu.biu.scapi.comm.LoadParties;
import edu.biu.scapi.comm.NaiveSuccess;
import edu.biu.scapi.comm.Party;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSender;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTSemiHonestExtensionSender;

/**
 * This application runs party one of Yao protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class App1 {
	
	/**
	 * Execute Yao protocol's party one.
	 * 
	 * @param args no arguments should be passed
	 */
	public static void main(String[] args) {
		//Create Party object to use in the OTExtension. 
		//The communication in Ot Extension is done in the native code and thus, it does not receive a channel but a party.
		Party party = null;
		try {
			party = new Party(InetAddress.getByName("127.0.0.1"), 7666);
		} catch (UnknownHostException e1) {
			// Should not occur since this is the localhost.
		}
		//Set up the communication with the other side and get the created channel.
		//This channel is used in protocol parts others than the OT.
		Channel channel = setCommunication();	
		
		try {
			//Create the Boolean circuit of AES.
			BooleanCircuit bc = new BooleanCircuit(new File("AES_Final-2.txt"));
			//Create the OT sender.
			OTBatchSender otSender = new OTSemiHonestExtensionSender(party,163,1);
			//Create the encryption scheme.
			MultiKeyEncryptionScheme mes = new AESFixedKeyMultiKeyEncryption();
			Date start = new Date();
			//Run the protocol multiple times.
			for(int i=0; i<100;i++){
				
				Date before = new Date();
				//Get the inputs of P1.
				ArrayList<Byte> ungarbledInput = readInputs();
				Date after = new Date();
				long time = (after.getTime() - before.getTime());
				System.out.println("read inputs took " +time + " milis");
				//Create Party one with the previous created objects.
				PartyOne p1 = new PartyOne(channel, bc, mes, otSender);
			
				//Run party 1 of Yao protocol.
				p1.run(ungarbledInput);
			}
			Date end = new Date();
			long time = (end.getTime() - start.getTime())/100;
			System.out.println("Yao's protocol party 1 took " +time + " milis");
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Create the inputs of party one from an input file.
	 * @return an Array contains the inputs for party one.
	 */
	private static ArrayList<Byte> readInputs() {
		File file = new File("AESPartyOneInputs.txt");
		
		Scanner scanner = null;
		try {
			scanner = new Scanner(file);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		ArrayList<Byte> inputs = new ArrayList<Byte>();
		//First, read the number of inputs.
		int inputsNumber = scanner.nextInt();
		//Read each input and set it in the inputs array.
		for (int i=0; i<inputsNumber; i++){
			inputs.add((byte) scanner.nextInt());
		}
		
		return inputs;
	}


	/**
	 * 
	 * Loads parties from a file and sets up the channel.
	 *  
	 * @return the channel with the other party.
	 */
	private static Channel setCommunication() {
		
		List<Party> listOfParties = null;
		
		LoadParties loadParties = new LoadParties("Parties1.properties");
	
		//Prepare the parties list.
		listOfParties = loadParties.getPartiesList();
	
		//Create the communication setup.
		CommunicationSetup commSetup = new CommunicationSetup();
	
		ConnectivitySuccessVerifier naive = new NaiveSuccess();
	
		System.out.print("Before call to prepare\n");
		
		Map<InetSocketAddress, Channel> connections = commSetup.prepareForCommunication(listOfParties, naive, 200000);
			
		//Return the channel with the other party. There was only one channel created.
		return (Channel)((connections.values()).toArray())[0];
	}
}
