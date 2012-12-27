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


import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.NoSuchPartyException;
import edu.biu.scapi.circuits.circuit.NotAllInputsSetException;
import edu.biu.scapi.circuits.circuit.Wire;
import edu.biu.scapi.circuits.encryption.CiphertextTooLongException;
import edu.biu.scapi.circuits.encryption.KeyNotSetException;
import edu.biu.scapi.circuits.encryption.TweakNotSetException;
import edu.biu.scapi.circuits.garbledCircuit.GarbledBooleanCircuit;
import edu.biu.scapi.circuits.garbledCircuit.GarbledWire;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;


public class YaoP2 implements Protocol{

	
	private Channel channel = null;
	private GarbledBooleanCircuit gbc = null;
	//private BitSet input = null;
	private BatchOtDdhSemiHonestReceiver bOTReceiver;
	private int[] inputBits;
	private DlogGroup dlog;
	private KeyDerivationFunction kdf;
	private int numOfSubSircuits = 0;
	
	
	/**
	 *  Creates the Yao's Protocol for Party 2.
	 * 
	 * @param channel the channel tfor communicating between the two parties
	 * @param dlog the dlog group to be used in the proctocol. Must be the same in both parties.
	 * @param kdf the key derivation function to be used in the protocol. Must be the same in both parties.
	 * @param inputBits the input of Party 2
	 */
	public YaoP2(Channel channel, DlogGroup dlog, KeyDerivationFunction kdf, int[] inputBits){
		
		this.channel = channel;
		this.dlog = dlog;
		this.inputBits = inputBits;
		this.kdf = kdf;
	}
	
	/**
	 *  Creates the Yao's Protocol for Party 2. This constructor should be used in the case where the circuit is sent
	 *  in pieces.
	 * 
	 * @param channel the channel for communicating between the two parties
	 * @param dlog the dlog group to be used in the proctocol. Must be the same in both parties.
	 * @param kdf the key derivation function to be used in the protocol. Must be the same in both parties.
	 * @param inputBits the input of Party 2.
	 * @param numOfSubSircuits the number of sub circuits. Should be corresponding to the number of sub circuits Party 1 sends.
	 */
	
	public YaoP2(Channel channel, DlogGroup dlog, KeyDerivationFunction kdf, int[] inputBits, int numOfSubSircuits){
		
		this.channel = channel;
		this.dlog = dlog;
		this.inputBits = inputBits;
		this.kdf = kdf;
		this.numOfSubSircuits = numOfSubSircuits;
	}
	
	@Override
	/**
	 * run the yao's protocol for party 2. 
	 * 
	 * 1. receives the garbled circuit from Party 1 including Party 1 garbled inputs
	 * 2. runs the oblivious transfer sub protocol in order to gets it's corresponding input keys
	 * 3. computes the circuit to obtain the result of the mutual function
	 * 
	 * Note: The result is not sent back to Party 1.
	 * 
	 */
	public void run() {

		//receive the garbled circuit and the input to P2 from P1
		try {
			
			
			//Thread.sleep(5000);
			Date start = new Date();
			
			gbc = (GarbledBooleanCircuit) channel.receive();

			
			Date end = new Date();
			long time = (end.getTime() - start.getTime());
			System.out.println("Yao's protocol receive circuit 1 took " +time + " milis");
			
			
			Date start2 = new Date();
			//create the OT as the sender
			bOTReceiver = new BatchOtDdhSemiHonestReceiver(channel, dlog, kdf, inputBits);
			
			//run the OT
			bOTReceiver.run();
			
			Date end2 = new Date();
			long time2 = (end2.getTime() - start2.getTime());
			System.out.println("Yao's protocol run OT 1 took " +time2 + " milis");
			
			
			
			
			//the output is the set of keys to P2
			ArrayList<SecretKey> resultingSecretKeys = bOTReceiver.getResult();
			List<Integer> inputWirsLabels = gbc.getInputWireLabels(2);
			
			int numberOfInputBits = inputBits.length;
			
			Map<Integer, GarbledWire> inputs = new HashMap<Integer, GarbledWire>();
			for (int i = 0; i < numberOfInputBits; i++) {
			      inputs.put(inputWirsLabels.get(i), new GarbledWire(inputWirsLabels.get(i), resultingSecretKeys.get(i)));
			}
			//retrieve the set of keys and set this input to the garbled circuit
			
			gbc.setInputs(inputs, 2);
			
			Date start3 = new Date();
			//compute the circuit and get the garbled wires
			Map<Integer, GarbledWire> garbledOutput = gbc.compute();
			
			//translate the resulting garbled wires into 0/1 regular wires.
			Map<Integer, Wire> Output = gbc.translate(garbledOutput);
			
			Date end3 = new Date();
			
			long time3 = (end3.getTime() - start3.getTime());
			System.out.println("Yao's protocol compute and translate circuit 1 took " +time3 + " milis");
			
			
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPartyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CiphertextTooLongException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyNotSetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (TweakNotSetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NotAllInputsSetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
	/**
	 * 
	 * /**
	 * run the yao's protocol for party 2 where the circuit is received in pieces.
	 * 
	 *  in order for Party 2 to start computing the circuit we need now to change the order and first do the oblivious transfer
	 *  so party 2 will have its input keys before computing the circuit
	 * 
	 * 1. runs the oblivious transfer sub protocol in order for party 2 to get its
	 * 2. receive the garbled circuit in pieces. The first sub circuit includes Party 1 garbled input.
	 * 3. computes the circuit to obtain the result of the mutual function
	 * 
	 * Note: The result is not sent back to Party 1.
	 * 
	 */
	public void runWithSubCircuits() {

		//receive the garbled circuit and the input to P2 from P1
		try {
			
			
			//Thread.sleep(5000);
			
			
			Date start2 = new Date();
			//create the OT as the sender
			bOTReceiver = new BatchOtDdhSemiHonestReceiver(channel, dlog, kdf, inputBits);
			
			//run the OT
			bOTReceiver.run();
			
			Date end2 = new Date();
			long time2 = (end2.getTime() - start2.getTime());
			System.out.println("Yao's protocol run OT 1 took " +time2 + " milis");
			
			
			Date start = new Date();
			
			//recieve the first piece of the garbled circuit. This piece includes party2 garbled input
			gbc = (GarbledBooleanCircuit) channel.receive();
			
			Date end = new Date();
			long time = (end.getTime() - start.getTime());
			System.out.println("Yao's protocol receive circuit 1 took " +time + " milis");
			
			//the output is the set of keys to P2
			ArrayList<SecretKey> resultingSecretKeys = bOTReceiver.getResult();
			List<Integer> inputWirsLabels = gbc.getInputWireLabels(2);
			
			int numberOfInputBits = inputBits.length;
			
			//prepare the garbled input 
			Map<Integer, GarbledWire> inputs = new HashMap<Integer, GarbledWire>();
			for (int i = 0; i < numberOfInputBits; i++) {
			      inputs.put(inputWirsLabels.get(i), new GarbledWire(inputWirsLabels.get(i), resultingSecretKeys.get(i)));
			}
			
			
			
			//retrieve the set of keys and set this input to the garbled circuit
			
			gbc.setInputs(inputs, 2);
			
			
			//compute the circuit and get the garbled wires
			Map<Integer, GarbledWire> garbledOutput = gbc.compute();
			
			start = new Date();
			for(int i=0; i<numOfSubSircuits-1;i++){
				
				//recieve the sub circuit
				gbc = (GarbledBooleanCircuit) channel.receive();
				
				//set the input 
				gbc.setInputs(garbledOutput, 1);
				
				//compute this sub circuit piece. Add the result to the garbledOutput variable that will be passed to the next sub circuit
				// We add the result instead of replacing since sub circuit 4 might need input from sub circuits 2 and 3.
				garbledOutput.putAll(gbc.compute());
				
			}
			end = new Date();
			
			time = (end.getTime() - start.getTime());
			System.out.println("Yao's protocol recieve and compute the rest of the sub circuits took " +time + " milis");
			
			start = new Date();
			//translate the resulting garbled wires into 0/1 regular wires. this is done on the last sub circuit.
			Map<Integer, Wire> Output = gbc.translate(garbledOutput);
			
			end = new Date();
			
			time = (end.getTime() - start.getTime());
			System.out.println("Yao's protocol translate circuit took " +time + " milis");
			
			
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPartyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CiphertextTooLongException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyNotSetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (TweakNotSetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NotAllInputsSetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
				
		
	}
	
	
	@Override
	public ProtocolOutput getOutput() {
		// TODO Auto-generated method stub
		return null;
	}
}
