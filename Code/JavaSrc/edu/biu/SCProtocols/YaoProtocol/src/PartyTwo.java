import java.io.IOException;
import java.io.Serializable;
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
import edu.biu.scapi.circuits.garbledCircuit.GarbledTablesHolder;
import edu.biu.scapi.circuits.garbledCircuit.GarbledWire;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchOnByteArrayROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchRBasicInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchReceiver;

/**
 * This is an implementation of party two of Yao protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class PartyTwo {

	OTBatchReceiver otReceiver;			//The OT object that used in the protocol.	
	GarbledBooleanCircuit circuit;		//The garbled circuit used in the protocol.
	Channel channel;					//The channel between both parties.
	
	/**
	 * Constructor that sets the parameters of the OT protocol and creates the garbled circuit.
	 * @param channel The channel between both parties.
	 * @param bc The boolean circuit that should be garbled.
	 * @param mes The encryption scheme to use in the garbled circuit.
	 * @param otReceiver The OT object to use in the protocol.
	 */
	public PartyTwo(Channel channel, BooleanCircuit bc, MultiKeyEncryptionScheme mes, OTBatchReceiver otReceiver){
		//Set the given parameters.
		this.channel = channel;
		this.otReceiver = otReceiver;
		
		//Create the garbled circuit.
		Date before = new Date();
		CircuitInput input = new FreeXORCircuitInput(bc, mes, false);
		circuit = new GarbledBooleanCircuitImp(input);
		Date after = new Date();
		long time = (after.getTime() - before.getTime());
		System.out.println("create circuit took " +time + " milis");
	}
	
	/**
	 * Runs the protocol.
	 * @param ungarbledInput The input for the circuit, each p2's input wire gets 0 or 1.
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws CheatAttemptException
	 * @throws InvalidDlogGroupException
	 */
	public void run(ArrayList<Byte> ungarbledInput) throws CheatAttemptException, ClassNotFoundException, IOException, InvalidDlogGroupException {
		Date startProtocol = new Date();
		Date start = new Date();
		//Receive garbled tables and translation table from p1.
		receiveCircuit();
		Date end = new Date();
		long time = (end.getTime() - start.getTime());
		System.out.println("Receive garbled tables and translation tables from p1 took " +time + " milis");
		
		start = new Date();
		//Receive P1 input keys and set them.
		receiveP1Inputs();
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("Receive and set inputs from p1 took " +time + " milis");
		
		start = new Date();
		//Run OT protocol in order to get the necessary keys without revealing any information.
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

	/**
	 * Receive the circuit's garbled tables and translation table.
	 * @throws CheatAttemptException
	 * @throws ClassNotFoundException
	 * @throws IOException
	 */
	private void receiveCircuit() throws CheatAttemptException, ClassNotFoundException, IOException {
		//Receive garbled tables.
		Serializable msg = channel.receive();
		if (!(msg instanceof GarbledTablesHolder)){
			throw new CheatAttemptException("the received message should be an instance of GarbledTablesHolder");
		}
		GarbledTablesHolder garbledTables = (GarbledTablesHolder) msg;

		//Receive translation table.
		msg = channel.receive();
		if (!(msg instanceof HashMap<?, ?>)){
			throw new CheatAttemptException("the received message should be an instance of HashMap<Integer, Byte>");
		}
		HashMap<Integer, Byte> translationTable = (HashMap<Integer, Byte>) msg;
			
		//Set garbled tables and translation table to the circuit.
		circuit.setGarbledTables(garbledTables);
		circuit.setTranslationTable(translationTable);
	}
	
	/**
	 * Receives party one input.
	 * @throws ClassNotFoundException
	 * @throws IOException
	 * @throws CheatAttemptException
	 */
	private void receiveP1Inputs() throws ClassNotFoundException, IOException, CheatAttemptException {
		//Receive the inputs as an ArrayList.
		Serializable msg = channel.receive();
		if (!(msg instanceof ArrayList<?>)){
			throw new CheatAttemptException("the received message should be an instance of ArrayList<SecretKey>");
		}
		ArrayList<SecretKey> inputs = (ArrayList<SecretKey>) msg;
		
		//Get party one input wires' indices.
		List<Integer> labels = null;
		try {
			labels = circuit.getInputWireIndices(1);
		} catch (NoSuchPartyException e) {
			// Should not occur since the party number is valid.
		}
  		int numberOfInputs = labels.size();
  		
  		//Put the inputs in HashMap, while the key for the map is the wire index and the value is the given key.
  		HashMap<Integer, GarbledWire> p1Inputs = new HashMap<Integer, GarbledWire>();
  		for (int i = 0; i < numberOfInputs; i++) {
  			int label = labels.get(i);
  			p1Inputs.put(label, new GarbledWire(inputs.get(i)));
  		}
		
  		//Set the input to the circuit.
  		circuit.setInputs(p1Inputs);
	}
	
	/**
	 * Run OT protocol in order to get party two input without revealing any information.
	 * @param sigmaArr Contains a byte indicates for each input wire which key to get.
	 * @return The output from the OT protocol, party tw oinputs.
	 * @throws ClassNotFoundException
	 * @throws IOException
	 * @throws CheatAttemptException
	 * @throws InvalidDlogGroupException
	 */
	private OTBatchOnByteArrayROutput runOTProtocol(ArrayList<Byte> sigmaArr) throws ClassNotFoundException, IOException, CheatAttemptException, InvalidDlogGroupException {
		//Create an OT input object with the given sigmaArr.
		OTBatchRInput input = new OTBatchRBasicInput(sigmaArr);
			
		//Run the Ot protocol.
		return (OTBatchOnByteArrayROutput) otReceiver.transfer(channel, input);
	}
	
	/**
	 * Compute the garbled circuit.
	 * @param otOutput The output from the OT protocol, which are party two inputs.
	 */
	private void computeCircuit(OTBatchOnByteArrayROutput otOutput) {
		//Get the output of the protocol.
		ArrayList<byte[]> keys = otOutput.getXSigmaArr();
		//Get party two input wires' indices.
		List<Integer> labels = null;
		try {
			labels = circuit.getInputWireIndices(2);
		} catch (NoSuchPartyException e) {
			// Should not occur since the party number is valid.
		}
  		int numberOfInputs = labels.size();
  		
  		//Put the inputs in HashMap, while the key for the map is the wire index and the value is the given key.
  		HashMap<Integer, GarbledWire> inputs = new HashMap<Integer, GarbledWire>();
  		for (int i = 0; i < numberOfInputs; i++) {
  			int label = labels.get(i);
  			inputs.put(label, new GarbledWire(new SecretKeySpec(keys.get(i), "")));
  		}
  		
  		//Set the input to the circuit.
		circuit.setInputs(inputs);
		
		//Compute the circuit.
  		HashMap<Integer, GarbledWire> garbledOutput = null;
		try {
			garbledOutput = circuit.compute();
		} catch (NotAllInputsSetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//Translate the result from compute.
  		Map<Integer, Wire> circuitOutput = circuit.translate(garbledOutput);
  	
	}
}
