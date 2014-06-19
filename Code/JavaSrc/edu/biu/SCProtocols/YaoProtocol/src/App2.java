import java.io.File;
import java.io.FileNotFoundException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
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
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchReceiver;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTSemiHonestExtensionReceiver;

/**
 * This application runs party two of Yao protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class App2 {
	
	/**
	 * @param args no arguments should be passed
	 */
	public static void main(String[] args) {
		Party party = null;
		try {
			party = new Party(InetAddress.getByName("127.0.0.1"), 7666);
		} catch (UnknownHostException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		//Set up the communication with the other side and get the created channel/
		Channel channel = setCommunication();	
		
		try {
			//Create the Boolean circuit of AES.
			BooleanCircuit bc = new BooleanCircuit(new File("AES_Final-2.txt"));
			//Create the OT sender.
			//OTBatchReceiver otReceiver = new OTSemiHonestDDHBatchOnByteArrayReceiver(dlog, kdf, random);
			OTBatchReceiver otReceiver = new OTSemiHonestExtensionReceiver(party,163,1);
			
			//Create the encryption scheme.
			MultiKeyEncryptionScheme mes = new AESFixedKeyMultiKeyEncryption();
			Date start = new Date();
			//Run the protocol multiple times.
			for(int i=0; i<100;i++){
				
				Date before = new Date();
				//Create Party two with the previous created objects.
				//ArrayList<Byte> ungarbledInput = readInputs();
				byte[] ungarbledInput = readInputsAsArray();
				Date after = new Date();
				long time = (after.getTime() - before.getTime());
				System.out.println("read inputs took " +time + " milis");
				
				//init the P1 yao protocol
				PartyTwo p2 = new PartyTwo(channel, bc, mes, otReceiver);
			
				//Run party two of Yao protocol.
				p2.run(ungarbledInput);
			}
			Date end = new Date();
			long time = (end.getTime() - start.getTime())/100;
			System.out.println("Yao's protocol party 2 took " +time + " milis");
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}		
	}
	
	/**
	 * Create the inputs of party two from an input file.
	 * @return an Array contains the inputs for party two.
	 */
	private static byte[] readInputsAsArray() {
		File file = new File("AESPartyTwoInputs.txt");
		
		Scanner scanner = null;
		try {
			scanner = new Scanner(file);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
			int inputsNumber = scanner.nextInt();
		byte[] inputs = new byte[inputsNumber];
	
		for (int i=0; i<inputsNumber; i++){
			inputs[i] =  (byte) scanner.nextInt();
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
		
		LoadParties loadParties = new LoadParties("Parties0.properties");
	
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
