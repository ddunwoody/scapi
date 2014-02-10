import java.io.File;
import java.io.FileNotFoundException;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
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
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSender;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.SemiHonest.OTSemiHonestDDHBatchOnByteArraySender;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.kdf.HKDF;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.prf.bc.BcHMAC;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;


public class App1 {
	
	/**
	 * @param args no arguments should be passed
	 */
	public static void main(String[] args) {
		DlogGroup dlog = null;
		KeyDerivationFunction kdf = null;
		try {
			//use the koblitz curve
			dlog = DlogGroupFactory.getInstance().getObject("DlogECF2m(K-233)", "Miracl");
			kdf = new HKDF(new BcHMAC());
		} catch (FactoriesException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		SecureRandom random = new SecureRandom();
		
		//set up the communication with the other side and get the created channel
		Channel channel = setCommunication();	
		
		//run the protocol multiple times
		try {
			
			BooleanCircuit bc = new BooleanCircuit(new File("AES_Final-2.txt"));
			OTBatchSender otSender = new OTSemiHonestDDHBatchOnByteArraySender(dlog, kdf, random);
			MultiKeyEncryptionScheme mes = new AESFixedKeyMultiKeyEncryption();
			Date start = new Date();
			for(int i=0; i<100;i++){
				
				Date before = new Date();
				ArrayList<Byte> ungarbledInput = readInputs();
				Date after = new Date();
				long time = (after.getTime() - before.getTime());
				System.out.println("read inputs took " +time + " milis");
				//init the P1 yao protocol
				PartyOne p1 = new PartyOne(channel, bc, mes, otSender);
			
				//run the yao's protocol as party 1
				p1.run(ungarbledInput);
			}
			Date end = new Date();
			long time = (end.getTime() - start.getTime())/100;
			System.out.println("Yao's protocol party 1 took " +time + " milis");
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	
			
	}
	
	
	private static ArrayList<Byte> readInputs() {
		File file = new File("AESpartyOneInputs.txt");
		
		Scanner scanner = null;
		try {
			scanner = new Scanner(file);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		ArrayList<Byte> inputs = new ArrayList<Byte>();
		int inputsNumber = scanner.nextInt();
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
	
		//prepare the parties list
		listOfParties = loadParties.getPartiesList();
	
		//create the communication setup
		CommunicationSetup commSetup = new CommunicationSetup();
	
		ConnectivitySuccessVerifier naive = new NaiveSuccess();
	
		System.out.print("Before call to prepare\n");
		
		Map<InetSocketAddress, Channel> connections = commSetup.prepareForCommunication(listOfParties, naive, 200000);
			
		//return the channel with the other party. There was only one channel created
		return (Channel)((connections.values()).toArray())[0];
	}
}
