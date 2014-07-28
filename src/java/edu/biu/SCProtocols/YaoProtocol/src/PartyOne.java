import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.circuits.garbledCircuit.CircuitCreationValues;
import edu.biu.scapi.circuits.garbledCircuit.GarblingParameters;
import edu.biu.scapi.circuits.garbledCircuit.FreeXORGarblingParameters;
import edu.biu.scapi.circuits.garbledCircuit.GarbledBooleanCircuit;
import edu.biu.scapi.circuits.garbledCircuit.GarbledBooleanCircuitImp;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSender;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionGeneralSInput;

/**
 * This is an implementation of party one of Yao protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class PartyOne {

	OTBatchSender otSender;			//The OT object that used in the protocol.	
	GarbledBooleanCircuit circuit;	//The garbled circuit used in the protocol.
	Channel channel;				//The channel between both parties.
	
	/**
	 * Constructor that sets the parameters of the OT protocol and creates the garbled circuit.
	 * @param channel The channel between both parties.
	 * @param bc The boolean circuit that should be garbled.
	 * @param mes The encryption scheme to use in the garbled circuit.
	 * @param otSender The OT object to use in the protocol.
	 */
	public PartyOne(Channel channel, BooleanCircuit bc, MultiKeyEncryptionScheme mes, OTBatchSender otSender){
		//Set the given parameters.
		this.channel = channel;
		this.otSender = otSender;
		
		//Create the garbled circuit.
		Date before = new Date();
		GarblingParameters input = new FreeXORGarblingParameters(bc, mes, false);
		circuit = new GarbledBooleanCircuitImp(input);
		Date after = new Date();
		long time = (after.getTime() - before.getTime());
		System.out.println("create circuit took " +time + " milis");
	}
	
	/**
	 * Runs the protocol.
	 * @param ungarbledInput The input for the circuit, each p1's input wire gets 0 or 1.
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws CheatAttemptException
	 * @throws InvalidDlogGroupException
	 */
	public void run(ArrayList<Byte> ungarbledInput) throws IOException, ClassNotFoundException, CheatAttemptException, InvalidDlogGroupException{
		Date startProtocol = new Date();
		Date start = new Date();
		//Constructs the garbled circuit.
		CircuitCreationValues values = circuit.garble();
		Date end = new Date();
		long time = (end.getTime() - start.getTime());
		System.out.println("generate keys and set tables took " +time + " milis");
		
		start = new Date();
		//Send garbled tables and the translation table to p2.
		channel.send(circuit.getGarbledTables());
		channel.send(circuit.getTranslationTable());
		end = new Date();
		time = (end.getTime() - start.getTime());
		System.out.println("Send garbled tables and translation tables took " +time + " milis");
		
		start = new Date();
		//Send p1 input keys to p2.
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

	/**
	 * Sends p1 input keys to p2.
	 * @param ungarbledInput The boolean input of each wire.
	 * @param allInputWireValues The keys for each wire.
	 * @throws IOException In case there was a problem to send via the channel.
	 */
	private void sendP1Inputs(ArrayList<Byte> ungarbledInput, Map<Integer, SecretKey[]> allInputWireValues) throws IOException {
		//Get the indices of p1 input wires.
		List<Integer> indices = null;
		try {
			indices = circuit.getInputWireIndices(1);
		} catch (NoSuchPartyException e) {
			// Should not occur since the party number is valid.
		}
  		int numberOfInputs = indices.size();
  		
  		//Create an array with the keys corresponding the given input.
  		ArrayList<SecretKey> inputs = new ArrayList<SecretKey> ();
  		for (int i = 0; i < numberOfInputs; i++) {
  			inputs.add(allInputWireValues.get(indices.get(i))[ungarbledInput.get(i)]);
  		}		
			
  		//Send the keys to p2.
		channel.send(inputs);
	}
	
	/**
	 * Runs OT protocol in order to send p2 the necessary keys without revealing any other information.
	 * @param allInputWireValues The keys for each wire.
	 * @throws ClassNotFoundException
	 * @throws IOException
	 * @throws CheatAttemptException
	 * @throws InvalidDlogGroupException
	 */
	private void runOTProtocol(Map<Integer, SecretKey[]> allInputWireValues) throws ClassNotFoundException, IOException, CheatAttemptException, InvalidDlogGroupException {
		//Get the indices of p2 input wires.
		List<Integer> partyTwoIndices = null;
		int size = 0;
		try {
			size = circuit.getNumberOfInputs(2);
			partyTwoIndices = circuit.getInputWireIndices(2);
		} catch (NoSuchPartyException e) {
			// Should not occur since the given party number is valid.
		}
		
		//Create and fill arrays with both keys of each input wire.
		int otWordSize = allInputWireValues.get(partyTwoIndices.get(0))[0].getEncoded().length;
		
		byte[] x0Arr = new byte[size * otWordSize];
		byte[] x1Arr = new byte[size * otWordSize];
		
		int index;
		for (int i=0; i<size; i++){
			index = partyTwoIndices.get(i);
			byte[] x0 = allInputWireValues.get(index)[0].getEncoded();
			byte[] x1 = allInputWireValues.get(index)[1].getEncoded();
			
			
			for(int j=0; j<otWordSize; j++){
				
				x0Arr[i*otWordSize + j] = x0[j];
				x1Arr[i*otWordSize + j] = x1[j];
			}
		}
		
		//Create an OT input object with the keys arrays.
		OTBatchSInput input = new OTExtensionGeneralSInput(x0Arr, x1Arr, size);
	
		//Run the OT's transfer phase.
		otSender.transfer(null, input);
		
	}

}
