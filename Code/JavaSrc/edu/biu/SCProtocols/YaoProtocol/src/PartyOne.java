import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.circuits.garbledCircuit.CircuitCreationValues;
import edu.biu.scapi.circuits.garbledCircuit.CircuitInput;
import edu.biu.scapi.circuits.garbledCircuit.FreeXORCircuitInput;
import edu.biu.scapi.circuits.garbledCircuit.GarbledBooleanCircuit;
import edu.biu.scapi.circuits.garbledCircuit.GarbledBooleanCircuitImp;
import edu.biu.scapi.circuits.garbledCircuit.GarbledBooleanCircuitSeedGenerationImp;
import edu.biu.scapi.circuits.garbledCircuit.MinimizeAESSetKeyCircuitInput;
import edu.biu.scapi.circuits.garbledCircuit.StandardCircuitInput;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchOnByteArraySInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSender;
import edu.biu.scapi.primitives.kdf.bc.BcKdfISO18033;
import edu.biu.scapi.primitives.prf.cryptopp.CryptoPpAES;

public class PartyOne {

	OTBatchSender otSender;
	BooleanCircuit bc;
	GarbledBooleanCircuit circuit;
	Channel channel;
	
	public PartyOne(Channel channel, BooleanCircuit bc, MultiKeyEncryptionScheme mes, OTBatchSender otSender){
		this.channel = channel;
		this.bc = bc;
		this.otSender = otSender;
		
		Date before = new Date();
		
		CircuitInput input = null;
	//	try {
			//input = new StandardCircuitInput(bc, mes, new BcKdfISO18033("SHA-1"), new SecureRandom());
			//input = new FreeXORCircuitInput(bc, mes, new BcKdfISO18033("SHA-1"));
		//} catch (FactoriesException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
		//}
		//input = new MinimizeAESSetKeyCircuitInput(bc, new CryptoPpAES(), new SecureRandom());
		//input = new StandardCircuitInput(bc, mes, new SecureRandom());
		input = new FreeXORCircuitInput(bc, mes);
		circuit = new GarbledBooleanCircuitImp(input);
			
		Date after = new Date();
		long time = (after.getTime() - before.getTime());
		System.out.println("create circuit took " +time + " milis");
	}
	
	public void run(ArrayList<Byte> ungarbledInput) throws IOException, ClassNotFoundException, CheatAttemptException, InvalidDlogGroupException{
		Date startProtocol = new Date();
		Date start = new Date();
		//Constructs the garbled circuit.
		CircuitCreationValues values = circuit.generateWireKeysAndSetTables(bc);
		Date end = new Date();
		long time = (end.getTime() - start.getTime());
		System.out.println("generate keys and set tables took " +time + " milis");
		
		start = new Date();
		//Send the garbled tables and the translation table to p2.
		channel.send(circuit.getGarbledTables());
		channel.send(circuit.getTranslationTable());
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("Send garbled tables and translation tables took " +time + " milis");
		
		start = new Date();
		//Put p1 inputs
		sendP1Inputs(ungarbledInput, values.getAllInputWireValues());
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("send inputs took " +time + " milis");
		
		start = new Date();
		//Run OT protocol in order to send p2 the necessary keys without revealing any information.
		runOTProtocol(values.getAllInputWireValues());
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("run OT took " +time + " milis");
		
		Date yaoEnd = new Date();
		long yaoTime = (yaoEnd.getTime() - startProtocol.getTime());
		System.out.println("run one protocol took " +yaoTime + " milis");
		
	}

	private void sendP1Inputs(ArrayList<Byte> ungarbledInput, Map<Integer, SecretKey[]> allInputWireValues) throws IOException {
		List<Integer> labels = null;
		try {
			labels = circuit.getInputWireLabels(1);
		} catch (NoSuchPartyException e) {
			// Should not occur since the party number is valid.
		}
  		int numberOfInputs = labels.size();
  		
  		ArrayList<SecretKey> inputs = new ArrayList<SecretKey> ();
  		
  		for (int i = 0; i < numberOfInputs; i++) {
  			int label = labels.get(i);
  			inputs.add(allInputWireValues.get(label)[ungarbledInput.get(i)]);
  		}		
			
		channel.send(inputs);
		
	}
	
	private void runOTProtocol(Map<Integer, SecretKey[]> allInputWireValues) throws ClassNotFoundException, IOException, CheatAttemptException, InvalidDlogGroupException {
		
		ArrayList<byte[]> x0Arr = new ArrayList<byte[]>();
		ArrayList<byte[]> x1Arr = new ArrayList<byte[]>();
		OTBatchSInput input = new OTBatchOnByteArraySInput(x0Arr, x1Arr);
		
		int size = 0;
		List<Integer> partyTwoLabels = null;
		try {
			size = circuit.getNumberOfInputs(2);
			partyTwoLabels = circuit.getInputWireLabels(2);
		} catch (NoSuchPartyException e) {
			// Should not occur since the given party number is valid.
		}
		int label;
		for (int i=0; i<size; i++){
			label = partyTwoLabels.get(i);
			x0Arr.add(allInputWireValues.get(label)[0].getEncoded());
			x1Arr.add(allInputWireValues.get(label)[1].getEncoded());
		}
		otSender.transfer(channel, input);
		
	}

}
