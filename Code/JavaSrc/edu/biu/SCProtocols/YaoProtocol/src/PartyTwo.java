import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.Wire;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.circuits.garbledCircuit.CircuitInput;
import edu.biu.scapi.circuits.garbledCircuit.FreeXORCircuitInput;
import edu.biu.scapi.circuits.garbledCircuit.GarbledBooleanCircuit;
import edu.biu.scapi.circuits.garbledCircuit.GarbledBooleanCircuitImp;
import edu.biu.scapi.circuits.garbledCircuit.GarbledBooleanCircuitSeedGenerationImp;
import edu.biu.scapi.circuits.garbledCircuit.GarbledWire;
import edu.biu.scapi.circuits.garbledCircuit.MinimizeAESSetKeyCircuitInput;
import edu.biu.scapi.circuits.garbledCircuit.StandardCircuitInput;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchOnByteArrayROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchRBasicInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchReceiver;
import edu.biu.scapi.primitives.kdf.bc.BcKdfISO18033;
import edu.biu.scapi.primitives.prf.cryptopp.CryptoPpAES;


public class PartyTwo {

	OTBatchReceiver otReceiver;
	BooleanCircuit bc;
	GarbledBooleanCircuit circuit;
	Channel channel;
	
	public PartyTwo(Channel channel, BooleanCircuit bc, MultiKeyEncryptionScheme mes, OTBatchReceiver otReceiver){
		this.channel = channel;
		this.bc = bc;
		this.otReceiver = otReceiver;
		Date before = new Date();
		
		CircuitInput input = null;
		//try {
			//input = new StandardCircuitInput(bc, mes, new BcKdfISO18033("SHA-1"), new SecureRandom());
			//input = new FreeXORCircuitInput(bc, mes, new BcKdfISO18033("SHA-1"));
		//} catch (FactoriesException e) {
			// TODO Auto-generated catch block
		//	e.printStackTrace();
		//}
		//input = new MinimizeAESSetKeyCircuitInput(bc, new CryptoPpAES(), new SecureRandom());
		//input = new StandardCircuitInput(bc, mes, new SecureRandom());
		
		input = new FreeXORCircuitInput(bc, mes);
		circuit = new GarbledBooleanCircuitImp(input);
		
		Date after = new Date();
		long time = (after.getTime() - before.getTime());
		System.out.println("create circuit took " +time + " milis");
	}
	
	public void run(ArrayList<Byte> ungarbledInput) throws CheatAttemptException, ClassNotFoundException, IOException, InvalidDlogGroupException {
		Date startProtocol = new Date();
		Date start = new Date();
		//Receive the garbled tables and the translation table from p1.
		receiveCircuit();
		Date end = new Date();
		long time = (end.getTime() - start.getTime());
		System.out.println("Receive garbled tables and translation tables from p1 took " +time + " milis");
		
		start = new Date();
		//Receive P1 inputs and set them.
		receiveP1Inputs();
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("Receive and set inputs from p1 took " +time + " milis");
		
		start = new Date();
		//Run OT protocol in order to get the necessary keys without p1 revealing any information.
		OTBatchOnByteArrayROutput output = runOTProtocol(ungarbledInput);
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("run OT took " +time + " milis");
		
		start = new Date();
		//Compute the circuit.
		computeCircuit(output);
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("computethe circuit took " +time + " milis");
		
		Date yaoEnd = new Date();
		long yaoTime = (yaoEnd.getTime() - startProtocol.getTime());
		System.out.println("run one protocol took " +yaoTime + " milis");
		
	}

	private void receiveCircuit() throws CheatAttemptException, ClassNotFoundException, IOException {
		
		Serializable msg = channel.receive();
		if (!(msg instanceof byte[][])){
			throw new CheatAttemptException("the received message should be an instance of byte[][], as the garbled tables.");
		}
		byte[][] garbledTables = (byte[][]) msg;

		msg = channel.receive();
		if (!(msg instanceof HashMap<?, ?>)){
			throw new CheatAttemptException("the received message should be an instance of HashMap<Integer, Byte>, as the translation table.");
		}
		HashMap<Integer, Byte> translationTable = (HashMap<Integer, Byte>) msg;
			
		circuit.setGarbledTables(garbledTables);
		circuit.setTranslationTable(translationTable);
	}
	
	private void receiveP1Inputs() throws ClassNotFoundException, IOException, CheatAttemptException {
		Serializable msg = channel.receive();
		if (!(msg instanceof ArrayList<?>)){
			throw new CheatAttemptException("the received message should be an instance of ArrayList<SecretKey>");
		}
		ArrayList<SecretKey> inputs = (ArrayList<SecretKey>) msg;
		
		List<Integer> labels = null;
		try {
			labels = circuit.getInputWireLabels(1);
		} catch (NoSuchPartyException e) {
			// Should not occur since the party number is valid.
		}
  		int numberOfInputs = labels.size();
  		
  		HashMap<Integer, GarbledWire> p1Inputs = new HashMap<Integer, GarbledWire>();
  		
  		for (int i = 0; i < numberOfInputs; i++) {
  			int label = labels.get(i);
  			p1Inputs.put(label, new GarbledWire(inputs.get(i)));
  		}
  		try {
			circuit.setInputs(p1Inputs, 1);
		} catch (NoSuchPartyException e) {
			// // Should not occur since the party number is valid.
		}
		
	}
	
	private OTBatchOnByteArrayROutput runOTProtocol(ArrayList<Byte> sigmaArr) throws ClassNotFoundException, IOException, CheatAttemptException, InvalidDlogGroupException {
		
		OTBatchRInput input = new OTBatchRBasicInput(sigmaArr);
			
		return (OTBatchOnByteArrayROutput) otReceiver.transfer(channel, input);
	}
	
	private void computeCircuit(OTBatchOnByteArrayROutput otOutput) {
		
		ArrayList<byte[]> keys = otOutput.getXSigmaArr();
		List<Integer> labels = null;
		try {
			labels = circuit.getInputWireLabels(2);
		} catch (NoSuchPartyException e) {
			// Should not occur since the party number is valid.
		}
  		int numberOfInputs = labels.size();
  		
  		HashMap<Integer, GarbledWire> inputs = new HashMap<Integer, GarbledWire>();
  		
  		for (int i = 0; i < numberOfInputs; i++) {
  			int label = labels.get(i);
  			inputs.put(label, new GarbledWire(new SecretKeySpec(keys.get(i), "")));
  		}
  		try {
			circuit.setInputs(inputs, 2);
		} catch (NoSuchPartyException e) {
			// Should not occur since the party number is valid.
		}
  		
  		Map<Integer, GarbledWire> garbledOutput = null;
		try {
			garbledOutput = circuit.compute();
		} catch (NotAllInputsSetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
  		Map<Integer, Wire> circuitOutput = circuit.translate(garbledOutput);
  		
  		
		
	}
}
