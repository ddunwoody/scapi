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
package edu.biu.scapi.circuits.garbledCircuit;

import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.Gate;
import edu.biu.scapi.circuits.encryption.HashingMultiKeyEncryption;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.PlaintextTooLongException;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.prg.PseudorandomGenerator;

/**
 * The {@code FreeXORGarbledBooleanCircuitUtil} uses the Free XOR technique that is explained in depth in <i>Free XOR Gates and 
 * Applications</i> by Validimir Kolesnikov and Thomas Schneider. <p>
 * This circuit's computing method chooses the wire labels according to the procedure delineated in the above described paper. 
 * It then replaces all XOR gates with {@code FreeXOR gates} and these gates can be computed without an encryption due to the way the 
 * wire's values were chosen. See the above paper also for a proof of security of this method. <p>
 * 
 * Note also that the {@link #compute()} method of {@code FreeXORGarbledBooleanCircuitUtil} is not different than the standard
 * {@code StandardGarbledBooleanCircuitUtil}. The reason for this is that we designed the circuit so that the circuit's computing method just
 * calls the gate's computing method. In the computing method, we use the interface {@link GarbledGate} to make our calls and thus the 
 * appropriate computing method for the dynamic type of the specified gate is automatically what is used. For the same reason, 
 * the {@link #verify(BooleanCircuit, Map)} method of {@code FreeXORGarbledBooleanCircuitUtil} is also identical to
 * {@code StandardGarbledBooleanCircuitutil}'s verifying method. </p>
 * 
 * @author Steven Goldfeder
 * 
 */
class FreeXORGarbledBooleanCircuitUtil implements CircuitTypeUtil {
	
	protected MultiKeyEncryptionScheme mes;
	
	// We save the XOR and XORNOT truth tables because they will be used many times and we want to avoid repeated creations.
	private BitSet XORNOTTruthTable;	
	private BitSet XORTruthTable;
	
	/**
	 * Sets the given MultiKeyEncryptionScheme.
	 * @param mes The concrete encryption object to use.
	 */
	FreeXORGarbledBooleanCircuitUtil(MultiKeyEncryptionScheme mes){
		this.mes = mes;
	}
	
	/**
	 * Default constructor. Uses HashingMultiKeyEncryption object.
	 */
	FreeXORGarbledBooleanCircuitUtil(){
		this(new HashingMultiKeyEncryption());
	}
	
	@Override
	public GarbledGate[] createGates(Gate[] ungarbledGates, GarbledTablesHolder garbledTablesHolder){
		// Get the XOR and XORNOT truth table to be used to test against for equality.
		BitSet XORTruthTable = getXORTruthTable();
		BitSet XORNOTTruthTable = getXORNOTTruthTable();
		
		GarbledGate[] gates = new GarbledGate[ungarbledGates.length];
	    int length = ungarbledGates.length;
		//For each gate, create the suitable Gate Object. 
		for (int gate = 0; gate < length; gate++) {
			//In case of XOR gate, create FreeXORGateSlim.
			if (ungarbledGates[gate].getTruthTable().equals(XORTruthTable)) {
				gates[gate] = new FreeXORGate(ungarbledGates[gate]);
			} 
			//In case of XORNOT gate, create FreeXORNOTGate.
			else if (ungarbledGates[gate].getTruthTable().equals(XORNOTTruthTable)) {
				gates[gate] = new FreeXORNOTGate(ungarbledGates[gate]);
			}
			//In case of standard gate, create a StandardGarbledGate.
			else {
				gates[gate] = createStandardGate(ungarbledGates[gate], garbledTablesHolder);
			}
		}
		return gates;
	}

	/**
	 * We extract the creation of the standard garbled gate in order to be able to derive and create different standard gates.<p>
	 * For example, in order to use the row reduction technique we derive this class and create RowReductionGate.
	 * @param ungarbledGate The gate we want to garble.
	 * @param garbledTablesHolder Holds the reference to the garbled tables.
	 * @return the created GarbledGate.
	 */
	protected GarbledGate createStandardGate(Gate ungarbledGate, GarbledTablesHolder garbledTablesHolder) {
		return new StandardGarbledGate(ungarbledGate, mes, garbledTablesHolder);
	}
	
	@Override
  	public CircuitCreationValues garble(BooleanCircuit ungarbledCircuit, GarbledTablesHolder garbledTablesHolder, 
			GarbledGate[] gates) {
		//Create maps to send to the functions that sample the keys and create the garbled tables. 
		Map<Integer, SecretKey[]> emptyWireValues = new HashMap<Integer, SecretKey[]>();
		
		//call the other garble (that actually perform the keys creation) with empty partial wire values.
		return garble(ungarbledCircuit, garbledTablesHolder, gates, emptyWireValues);
	}	
	
	@Override
	public CircuitCreationValues garble(BooleanCircuit ungarbledCircuit, GarbledTablesHolder garbledTablesHolder, 
			GarbledGate[] gates, Map<Integer, SecretKey[]> partialWireValues) {
		
		Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
		Map<Integer, SecretKey[]> allInputWireValues = null;
		Map<Integer, SecretKey[]> allOutputWireValues = null;
		HashMap<Integer, Byte> translationTable = new HashMap<Integer, Byte>();
		Gate[] ungarbledGates = ungarbledCircuit.getGates();
		byte[] globalKeyOffset = null;
		
		//In case the given partialKeys are the output keys, sample the non output keys.
		if (partialWireValues.containsKey(ungarbledCircuit.getOutputWireLabels()[0])){
			
			//Set the given keys and signal bits.
			allOutputWireValues = partialWireValues;
			
			allWireValues.putAll(partialWireValues);
			//Generate the translation table out of the given output keys.
			for (int n : ungarbledCircuit.getOutputWireLabels()) {
				//Signal bit is the last bit of k0.
				byte[] k0 = allWireValues.get(n)[0].getEncoded();
				translationTable.put(n, (byte) (k0[k0.length-1] & 1));	
			}
			
			
			//Deduce the global key offset from allOutputWireValues.
			globalKeyOffset = extractGlobalkey(allOutputWireValues, ungarbledCircuit.getOutputWireLabels()[0]);
			
			//Create the keys of the non-output wires.
			createNonOutputWireValues(ungarbledGates, allWireValues, globalKeyOffset);
			
			int label;
			allInputWireValues = new HashMap<Integer, SecretKey[]>();
			ArrayList<Integer> inputWires = null;
			int length = ungarbledCircuit.getNumberOfParties();
			//Fill the input wire's keys and signal bits.
			for (int i=1; i<=length; i++){
				try {
					inputWires = ungarbledCircuit.getInputWireLabels(i);
				} catch (NoSuchPartyException e) {
					// Should not occur since there always at least one party.
				}
				for (int j=0; j<inputWires.size(); j++){
					label = inputWires.get(j);
					
					allInputWireValues.put(label, allWireValues.get(label));
				}
			}
			
		//In case the given partialKeys are not the output keys, they can be the input keys or empty.
		} else{
			//In case the partial keys are not empty, they contain the input keys.
			if (!partialWireValues.isEmpty()){
				//Set the given keys and signal bits.
				allInputWireValues = partialWireValues;
				
				//Deduce the global key offset from allInputWireValues.
				try {
					globalKeyOffset = extractGlobalkey(allInputWireValues, ungarbledCircuit.getInputWireLabels(1).get(0));
				} catch (NoSuchPartyException e) {
					// Should not occur since there always at least one party.
				}
			//In case the partial keys are empty, sample all keys.
			} else {
				/*
				 * The globalKeyOffset is a randomly chosen bit sequence that is the same size as the key and will be used to create the 
				 * garbled wire's values.
				 * We used generate key since this way globalKeyOfset will always be the size of the key. 
				 * See Free XOR Gates and Applications by Validimir Kolesnikov and Thomas Schneider.
				 */
				globalKeyOffset = mes.generateKey().getEncoded();
				/*
				 * Setting the last bit to 1. This follows algorithm 1 step 2 part A of Free XOR Gates and Applications by Validimir 
				 * Kolesnikov and Thomas Schneider.
				 * This algorithm calls for XORing the Wire values with R and the signal bit with 1. So, we set the last bit of R to 1 and 
				 * this will be XOR'd with the last bit of the wire value, which is the signal bit in our implementation.
				 */
				globalKeyOffset[globalKeyOffset.length - 1] |= 1;
				
				//Sample input keys.
				allInputWireValues = new HashMap<Integer, SecretKey[]>();
				for (int i=1; i<=ungarbledCircuit.getNumberOfParties(); i++){
					ArrayList<Integer> inputWireLabels = null;
					try {
						inputWireLabels = ungarbledCircuit.getInputWireLabels(i);
					} catch (NoSuchPartyException e) {
						// should not occur since the number is a valid party number
					}
					for (int w : inputWireLabels) {
						//Samples random key. The other key will be calculated via XOR with the globalKeyOffset.
						SecretKey zeroValue = mes.generateKey();
						sampleInputKeys(allInputWireValues, globalKeyOffset, w, zeroValue);
					}
				}
			}	
			//Set the given keys and signal bits.
			allWireValues.putAll(allInputWireValues);
			
			allOutputWireValues = new HashMap<Integer, SecretKey[]>();
			translationTable = new HashMap<Integer, Byte>();
			
			//Create the keys of the non-input wires.
			createNonInputWireValues(ungarbledGates, allWireValues, globalKeyOffset);
			
			//Fill the the output wire values to be used in the following sub circuit
			for (int n : ungarbledCircuit.getOutputWireLabels()) {
				
				//Add both values of output wire labels to the allOutputWireLabels Map that was passed as a parameter.
				allOutputWireValues.put(n, allWireValues.get(n));
				
				//Signal bit is the last bit of k0.
				byte[] k0 = allWireValues.get(n)[0].getEncoded();
				translationTable.put(n, (byte) (k0[k0.length-1] & 1));			}
		}
		
		//now that we have all keys, we can create the garbled tables.
		try {
			createGarbledTables(gates, garbledTablesHolder, ungarbledGates, allWireValues);
		} catch (InvalidKeyException e) {
			// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
		} catch (IllegalBlockSizeException e) {
			// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
		} catch (PlaintextTooLongException e) {
			// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
		} 
		
		return new CircuitCreationValues(allInputWireValues, allOutputWireValues, translationTable);		
	}
	
	
	
	/**
	 * Generates the input wire keys and signal bits.
	 * @param allWireValues A map that contains both keys for each wire.
	 * @param globalKeyOffset The FreeXOR circuit's delta.
	 * @param zeroValue value of the wire's zero key. The other key will be calculated via XOR with the globalKeyOffset.
	 */
	protected void sampleInputKeys(Map<Integer, SecretKey[]> allWireValues, byte[] globalKeyOffset, int w, SecretKey zeroValue) {
		SecretKey oneValue;
		byte[] zeroValueBytes = zeroValue.getEncoded();
		
		//Calculate k1 by xoring k0 with globalKeyOffset
		byte[] oneValueBytes = new byte[zeroValueBytes.length];
		for (int i = 0; i < zeroValueBytes.length; i++) {
			oneValueBytes[i] = (byte) (zeroValueBytes[i] ^ globalKeyOffset[i]);
		}
		oneValue = new SecretKeySpec(oneValueBytes, "");
		//Put the keys in the map.
		allWireValues.put(w, new SecretKey[] { zeroValue, oneValue });
	}

	/**
	 * Creates the truth table of XORNOT. <P>
	 * For efficiency reasons, the truth table will be created the first time this function is called.
	 * Further calls will return the existed table.
	 */
	private BitSet getXORNOTTruthTable() {
		if (XORNOTTruthTable == null){
			XORNOTTruthTable = new BitSet();
			XORNOTTruthTable.set(0);
			XORNOTTruthTable.set(3);
		}
		return XORNOTTruthTable;
	}

	/**
	 * Creates the truth table of XOR.<P>
	 * For efficiency reasons, the truth table will be created the first time this function is called.
	 * Further calls will return the existed table.
	 */
	private BitSet getXORTruthTable() {
		if (XORTruthTable == null){
			XORTruthTable = new BitSet();
			XORTruthTable.set(1);
			XORTruthTable.set(2);
		}
		return XORTruthTable;
	}
	
	/**
	 * Creates garbled tables for the gates of this circuit. 
	 * @param gates The gates of this circuit.
	 * @param garbledTablesHolder Contains the pointer to the garbled tables.
	 * @param ungarbledGates The gates that should be garbled.
	 * @param allWireValues A map that contains both keys for each wire.
	 */
	protected void createGarbledTables(GarbledGate[] gates, GarbledTablesHolder garbledTablesHolder, Gate[] ungarbledGates, Map<Integer, SecretKey[]> allWireValues) throws InvalidKeyException, IllegalBlockSizeException, PlaintextTooLongException {
			
		// Get the XOR and XORNOT truth table to be used to test against for equality.
		BitSet XORTruthTable = getXORTruthTable();
		BitSet XORNOTTruthTable = getXORNOTTruthTable();
				
		//For each Standard gate, create the suitable StandardGarbledGate object. 
		//Free XOR gate and Free XOR NOT gates do not have a garbled tables, thus they should not be created.
		for (int gate = 0; gate < ungarbledGates.length; gate++) {
			
			if (!ungarbledGates[gate].getTruthTable().equals(XORTruthTable) && !(ungarbledGates[gate].getTruthTable().equals(XORNOTTruthTable))) {
				((StandardGarbledGate) gates[gate]).createGarbledTable(ungarbledGates[gate], allWireValues);
			}
		}
	}
	
	/**
	 * Creates the keys of the non-input wires.
	 * @param ungarbledGates The gates that should be garbled.
	 * @param allWireValues A map that contains both keys for each wire.
	 * @param globalKeyOffset The FREE XOR delta.
	 */
	protected void createNonInputWireValues(Gate[] ungarbledGates, Map<Integer, SecretKey[]> allWireValues, byte[] globalKeyOffset){
		// Get the XOR and XORNOT truth table to be used to test against for equality.
		BitSet XORTruthTable = getXORTruthTable();
		BitSet XORNOTTruthTable = getXORNOTTruthTable();
		
		//Generate both keys for each output wire of each gate.
		for (int gate = 0; gate < ungarbledGates.length; gate++) {
			//XOR gate.
			if (ungarbledGates[gate].getTruthTable().equals(XORTruthTable)) {
				generateXORValues(ungarbledGates[gate], allWireValues, globalKeyOffset);

			} 
			//XOR NOT gate.
			else if (ungarbledGates[gate].getTruthTable().equals(XORNOTTruthTable)) {
				generateXORNOTValues(ungarbledGates[gate], allWireValues, globalKeyOffset);
			}
			//Standard gate.
			else {
				byte[] zeroValueBytes = mes.generateKey().getEncoded();//Generate the first value.
				generateStandardValues(ungarbledGates[gate], allWireValues, globalKeyOffset, zeroValueBytes);
			}
		}
	}

	/**
	 * Generates keys for standard gate.
	 * @param ungarbledGate The gate that should be garbled.
	 * @param allWireValues A map that contains both keys for each wire.
	 * @param globalKeyOffset The FREE XOR delta.
	 * @param zeroValueBytes The value of the first key. 
	 * We get it as a parameter because the generation of the first key can be done by the encryption scheme or by the prg, depending in the caller function.
	 * Thus, the caller function generates the first key and this function does the rest.
	 */
	protected void generateStandardValues(Gate ungarbledGate, Map<Integer, SecretKey[]> allWireValues, byte[] globalKeyOffset, byte[] zeroValueBytes) {
		
		//Call the function that calculate k1 from k0 and globalKeyOffset.
		calcK1AndPutInMaps(allWireValues, globalKeyOffset, zeroValueBytes, null, ungarbledGate.getOutputWireLabels()[0]);
	}

	/**
	 * Gets k0 and calculate k1 according to it.
	 * Puts the keys and signal bit in the maps. 
	 * @param allWireValues A map that contains both keys for each wire.
	 * @param globalKeyOffset The FREE XOR delta.
	 * @param zeroValueBytes The value of the first key.
	 * @param label The label of the wire we generate keys for.
	 */
	protected void calcK1AndPutInMaps(Map<Integer, SecretKey[]> allWireValues, byte[] globalKeyOffset, byte[] zeroValueBytes, byte[] oneValueBytes, int label) {
		SecretKey zeroValue;
		SecretKey oneValue;
		
		if (oneValueBytes == null){
			oneValueBytes = new byte[zeroValueBytes.length];
			
			//Calculate the k1 value.
			for (int i = 0; i < zeroValueBytes.length; i++) {
				oneValueBytes[i] = (byte) (zeroValueBytes[i] ^ globalKeyOffset[i]);
			}
		} else{
			zeroValueBytes = new byte[oneValueBytes.length];
			
			//Calculate the k1 value.
			for (int i = 0; i < oneValueBytes.length; i++) {
				zeroValueBytes[i] = (byte) (oneValueBytes[i] ^ globalKeyOffset[i]);
			}
		}
		
		zeroValue = new SecretKeySpec(zeroValueBytes, "");
		oneValue = new SecretKeySpec(oneValueBytes, "");

		//Put the keys in the map.
		allWireValues.put(label, new SecretKey[] { zeroValue, oneValue });
	}

	/**
	 * Generates keys for XORNOT gate.
	 * @param ungarbledGate The gate that should be garbled.
	 * @param allWireValues A map that contains both keys for each wire.
	 * @param globalKeyOffset The FREE XOR delta.
	 */
	private void generateXORNOTValues(Gate ungarbledGate, Map<Integer, SecretKey[]> allWireValues, byte[] globalKeyOffset) {
		
		//calculate the value of k1, by xoring all k0 of the input wires.
		byte[] oneOutputBytes = allWireValues.get(ungarbledGate.getInputWireLabels()[0])[0].getEncoded();// bytes of first input
		for (int i = 1; i < ungarbledGate.getInputWireLabels().length; i++) {
			byte[] nextInput = allWireValues.get(ungarbledGate.getInputWireLabels()[i])[0].getEncoded();
			for (int currentByte = 0; currentByte < oneOutputBytes.length; currentByte++) {
				oneOutputBytes[currentByte] ^= (byte) nextInput[currentByte];
			}
		}
		
		//Call the function that calculate k0 from k1 and globalKeyOffset.
		calcK1AndPutInMaps(allWireValues, globalKeyOffset, null, oneOutputBytes, ungarbledGate.getOutputWireLabels()[0]);
		
	}

	/**
	 * Generates keys for XOR gate.
	 * @param ungarbledGate The gate that should be garbled.
	 * @param allWireValues A map that contains both keys for each wire.
	 * @param globalKeyOffset The FREE XOR delta.
	 */
	private void generateXORValues(Gate ungarbledGate, Map<Integer, SecretKey[]> allWireValues, byte[] globalKeyOffset) {
		//calculate the value of k0, by xoring all k0 of the input wires.
		// Get the bytes of first input
		byte[] zeroValueBytes = allWireValues.get(ungarbledGate.getInputWireLabels()[0])[0].getEncoded();
		for (int i = 1; i < ungarbledGate.getInputWireLabels().length; i++) {
			
			byte[] nextInput = allWireValues.get(ungarbledGate.getInputWireLabels()[i])[0].getEncoded();
			for (int currentByte = 0; currentByte < zeroValueBytes.length; currentByte++) {
				zeroValueBytes[currentByte] ^= nextInput[currentByte];
			}
		}
		
		//Call the function that calculate k1 from k0 and globalKeyOffset.
		calcK1AndPutInMaps(allWireValues, globalKeyOffset, zeroValueBytes, null, ungarbledGate.getOutputWireLabels()[0]);
	}

	/**
	 * Extracts the global key from the given wire's label.
	 * @param allInputWireValues A map containing all keys.
	 * @param label that exist in the map.
	 */
	protected byte[] extractGlobalkey(Map<Integer, SecretKey[]> allInputWireValues, int label) {
		
		//Get the keys of the given wire's label.
		SecretKey zeroValue = allInputWireValues.get(label)[0];
		SecretKey oneValue = allInputWireValues.get(label)[1];
		byte[] zeroValueBytes = zeroValue.getEncoded();
		byte[] oneValueBytes = oneValue.getEncoded();
		
		byte[] globalKeyOffset = new byte[zeroValueBytes.length];
		//Calculate the global key by xoring both keys.
		for (int i = 0; i < zeroValueBytes.length; i++) {
			globalKeyOffset[i] = (byte) (oneValueBytes[i] ^ zeroValueBytes[i]);
		}
		return globalKeyOffset;
	}
	
	/**
	 * Creates the keys of the non-output wires.
	 * @param ungarbledGates The gates that should be garbled.
	 * @param allWireValues A map that contains both keys for each wire.
	 * @param globalKeyOffset The FREE XOR delta.
	 */
	private void createNonOutputWireValues(Gate[] ungarbledGates, Map<Integer, SecretKey[]> allWireValues, byte[] globalKeyOffset) {
		// Get the XOR and XORNOT truth table to be used to test against for equality.
		BitSet XORTruthTable = getXORTruthTable();
		BitSet XORNOTTruthTable = getXORNOTTruthTable();
						
		// Create the keys according to the specific gate. 
		// When we process a gate, we should have its output wires' keys in order to create the input keys.
		// In order to let that happen, notice that we go through the circuit from the end to the beginning.
		// Tthe gates are sorted in topological order, and that ensure us that when we get to a specific gate it will have the output keys.
		for (int gate = ungarbledGates.length-1; gate >= 0; gate--) {
			//XOR gate.
			if (ungarbledGates[gate].getTruthTable().equals(XORTruthTable)) {
				generateBothXORValues(ungarbledGates[gate], allWireValues, globalKeyOffset);
			
			//XORNOT gate.
			} else if (ungarbledGates[gate].getTruthTable().equals(XORNOTTruthTable)) {
				generateBothXORNOTValues(ungarbledGates[gate], allWireValues, globalKeyOffset);
			
			//Standard gate.
			}else {
				generateBothStandardValues(ungarbledGates[gate], allWireValues, globalKeyOffset);
			}
		}
	}
	
	/**
	 * Generates k0, k1 of both input wires of a standard gate, in a free xor circuit. <p>
	 * Meaning, k0 and k1 should be the xor of each other and a delta.
	 * @param ungarbledGate The gate that should be garbled
	 * @param allWireValues A map that contains both keys for each wire.
	 * @param globalKeyOffset The FREE XOR delta.
	 */
	protected void generateBothStandardValues(Gate ungarbledGate, Map<Integer, SecretKey[]> allWireValues, byte[] globalKeyOffset) {
		
		// Generate values are for the first input wire.
		// Generate k0 value.
		byte[] zeroKeyBytes = mes.generateKey().getEncoded();
		// Call the function that calculate the corresponding k1 and put the values in the map.
		calcK1AndPutInMaps(allWireValues, globalKeyOffset, zeroKeyBytes, null, ungarbledGate.getInputWireLabels()[0]);
		
		// Generate values are for the second input wire.
		// Generate k0 value.
		zeroKeyBytes = mes.generateKey().getEncoded();
		// Call the function that calculate the corresponding k1 and put the values in the map.
		calcK1AndPutInMaps(allWireValues, globalKeyOffset, zeroKeyBytes, null, ungarbledGate.getInputWireLabels()[1]);
	}

	/**
	 * Generates k0, k1 of both input wires of a XORNOT gate. <p>
	 * @param ungarbledGate The gate that should be garbled
	 * @param allWireValues A map that contains both keys for each wire.
	 * @param globalKeyOffset The FREE XOR delta.
	 */
	private void generateBothXORNOTValues(Gate ungarbledGate, Map<Integer, SecretKey[]> allWireValues, byte[] globalKeyOffset) {
		
		// Create the first input wire's keys
		byte[] zeroKeyBytes = mes.generateKey().getEncoded();
		// Calculate the corresponding k1 and put the values in the map.
		calcK1AndPutInMaps(allWireValues, globalKeyOffset, zeroKeyBytes, null, ungarbledGate.getInputWireLabels()[0]);
		
		// Create the second input wire's keys
		byte[] oneKeyBytes = new byte[zeroKeyBytes.length];
		//k1 of the second wire is k0 of the first wire xor with k0 of the output wire.
		byte[] gateOutputKey = allWireValues.get(ungarbledGate.getOutputWireLabels()[0])[0].getEncoded();
		for (int i = 0; i < zeroKeyBytes.length; i++) {
			oneKeyBytes[i] = (byte) (zeroKeyBytes[i] ^ gateOutputKey[i]);
		}
		// Calculate the corresponding k0 and put the values in the map.
		calcK1AndPutInMaps(allWireValues, globalKeyOffset, null, oneKeyBytes, ungarbledGate.getInputWireLabels()[1]);
	}

	/**
	 * Generates k0, k1 of both input wires of a XOR gate. <p>
	 * @param ungarbledGate The gate that should be garbled
	 * @param allWireValues A map that contains both keys for each wire.
	 * @param globalKeyOffset The FREE XOR delta.
	 */
	private void generateBothXORValues(Gate ungarbledGate, Map<Integer, SecretKey[]> allWireValues, byte[] globalKeyOffset) {
		
		
		// Create the first input wire's keys
		byte[] w0ZeroKeyBytes = mes.generateKey().getEncoded();
		// Calculate the corresponding k1 and put the values in the map.
		calcK1AndPutInMaps(allWireValues, globalKeyOffset, w0ZeroKeyBytes, null, ungarbledGate.getInputWireLabels()[0]);
		
		// Create the second input wire's keys
		byte[] w1ZeroKeyBytes = new byte[w0ZeroKeyBytes.length];
		//k0 of the second wire is k0 of the first wire xor with k0 of the output wire.
		byte[] gateOutputKey = allWireValues.get(ungarbledGate.getOutputWireLabels()[0])[0].getEncoded();
		for (int i = 0; i < w0ZeroKeyBytes.length; i++) {
			w1ZeroKeyBytes[i] = (byte) (w0ZeroKeyBytes[i] ^ gateOutputKey[i]);
		}
		// Calculate the corresponding k1 and put the values in the map.
		calcK1AndPutInMaps(allWireValues, globalKeyOffset, w1ZeroKeyBytes, null, ungarbledGate.getInputWireLabels()[1]);
	}
	
	@Override
	public CircuitSeedCreationValues garble(BooleanCircuit ungarbledCircuit, GarbledTablesHolder garbledTablesHolder, 
			GarbledGate[] gates, PseudorandomGenerator prg, byte[] seed, CryptographicHash hash) throws InvalidKeyException {
		
		Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
		Gate[] ungarbledGates = ungarbledCircuit.getGates();
		
		//Call the function thast actually performs the keys generation.
		CircuitCreationValues values = sampleSeedKeys(ungarbledCircuit, prg, seed, allWireValues);
		
		//Now that all wires have garbled values, we create the garbled tables.
		byte[] hashedTables = null;
		try {
			hashedTables = createGarbledTables(garbledTablesHolder, gates, ungarbledGates, allWireValues, hash);
		} catch (PlaintextTooLongException e) {
			// Should not occur since the plaintext length is valid 
		} catch (IllegalBlockSizeException e) {
			// Should not occur since the block size is valid
		} 
				
		return new CircuitSeedCreationValues(values.getAllInputWireValues(), values.getAllOutputWireValues(), values.getOutputWireValues(), hashedTables);
	}
	
	/**
	 * Samples the keys for the garbled wires.
	 * @param ungarbledCircuit The circuit that should be garbled.
	 * @param prg To use in order to generate the keys.
	 * @param seed To initialize the prg.
	 * @param allWireValues An empty map that will be filled with keys during the function execution.
	 * @return the created keys of each input and output wire and the translation table.
	 * @throws InvalidKeyException
	 */
	private CircuitCreationValues sampleSeedKeys(BooleanCircuit ungarbledCircuit, PseudorandomGenerator prg, byte[] seed, Map<Integer, SecretKey[]> allWireValues) throws InvalidKeyException {
		Map<Integer, SecretKey[]> allInputWireValues = new HashMap<Integer, SecretKey[]>();
		Map<Integer, SecretKey[]> allOutputWireValues = new HashMap<Integer, SecretKey[]>();
		HashMap<Integer, Byte> translationTable = new HashMap<Integer, Byte>();
		
		//Sets the given seed as the prg key.
		prg.setKey(new SecretKeySpec(seed, ""));
		
		//The globalKeyOffset is a randomly chosen bit sequence that is the same size as the key and will be used to create the garbled wire's values.
		int keySize = mes.getCipherSize();
		byte[] globalKeyOffset = new byte[keySize];
		prg.getPRGBytes(globalKeyOffset, 0, keySize);
		
		/*
		 * Setting the last bit to 1. This follows algorithm 1 step 2 part A of Free XOR Gates and Applications by Validimir 
		 * Kolesnikov and Thomas Schneider.
		 * This algorithm calls for XORing the Wire values with R and the signal bit with 1. So, we set the last bit of R to 1 and 
		 * this will be XOR'd with the last bit of the wire value, which is the signal bit in our implementation.
		 */
		globalKeyOffset[globalKeyOffset.length - 1] |= 1;
		
		//Set input wire keys and the related signal bits.
		for (int i=1; i <= ungarbledCircuit.getNumberOfParties(); i++){
			ArrayList<Integer> inputWireLabels = null;
			try {
				inputWireLabels = ungarbledCircuit.getInputWireLabels(i);
			} catch (NoSuchPartyException e) {
				// should not occur since the number is a valid party number
			}
			for (int w : inputWireLabels) {
				byte[] zeroValueBytes = new byte[keySize];
				prg.getPRGBytes(zeroValueBytes, 0, keySize);
				sampleInputKeys(allInputWireValues, globalKeyOffset, w, new SecretKeySpec(zeroValueBytes, ""));
	
			}
		}
		
		//Set the keys of the input wires
		allWireValues.putAll(allInputWireValues);	
		
		//Create the keys of the non-input wires.
		createNonInputWireValuesFromSeed(ungarbledCircuit.getGates(), allWireValues, globalKeyOffset, keySize, prg);

		//Fill the the output wire values to be used in the following sub circuit
		for (int n : ungarbledCircuit.getOutputWireLabels()) {
			
			//Add both values of output wire labels to the allOutputWireLabels Map that was passed as a parameter.
			allOutputWireValues.put(n, allWireValues.get(n));
			
			//Signal bit is the last bit of k0.
			byte[] k0 = allWireValues.get(n)[0].getEncoded();
			translationTable.put(n, (byte) (k0[k0.length-1] & 1));	
		}
		
		return new CircuitCreationValues(allInputWireValues, allOutputWireValues, translationTable);
	}
	
	/**
	 * Creates the gates and garbled tables of this circuit.
	 * Compute the hash function on the garbled tables. 
	 * @param garbledTablesHolder Holds the pointer to the garbled tables.
	 * @param gates Garbled gates of this circuit.
	 * @param ungarbledGates The gates that should be garbled.
	 * @param allWireValues An empty map that will be filled with keys during the function execution.
	 * @param hash The CryptographicHash function to use.
	 * @return the result of the hash function on the garbled tables.
	 */
	private byte[] createGarbledTables(GarbledTablesHolder garbledTablesHolder, GarbledGate[] gates, Gate[] ungarbledGates, 
			Map<Integer, SecretKey[]> allWireValues, CryptographicHash hash) 
			throws InvalidKeyException, IllegalBlockSizeException, PlaintextTooLongException{
		
		byte[][] garbledTables = garbledTablesHolder.getGarbledTables();
		
		// Get the XOR and XORNOT truth table to be used to test against for equality.
		BitSet XORTruthTable = getXORTruthTable();
		BitSet XORNOTTruthTable = getXORNOTTruthTable();
				
		//For each gate that is not XOR or XORNOT gates, create the suitable gate object. 
		for (int gate = 0; gate < ungarbledGates.length; gate++) {
			//In case of XOR gate, create FreeXORGateSlim.
			if ((!ungarbledGates[gate].getTruthTable().equals(XORTruthTable)) && !(ungarbledGates[gate].getTruthTable().equals(XORNOTTruthTable))){
				((StandardGarbledGate) gates[gate]).createGarbledTable(ungarbledGates[gate], allWireValues);
				//Update the hash with the new garbled table.
				hash.update(garbledTables[gate], 0, garbledTables[gate].length);
			}
		}
		
		//Compute the hash function.
		byte[] hashedTables = new byte[hash.getHashedMsgSize()];
		hash.hashFinal(hashedTables, 0);
		
		return hashedTables;
		
	}
	
	/**
	 * Creates the keys of the non-input wires using the given prg and seed.
	 * @param ungarbledGates The gates that should be garbled.
	 * @param allWireValues A map that contains both keys for each wire.
	 * @param globalKeyOffset The FREE XOR delta.
	 * @param keySize
	 * @param prg 
	 */
	private void createNonInputWireValuesFromSeed(Gate[] ungarbledGates, Map<Integer, SecretKey[]> allWireValues,
		byte[] globalKeyOffset, int keySize, PseudorandomGenerator prg) {
		// Get the XOR and XORNOT truth table to be used to test against for equality
		BitSet XORTruthTable = getXORTruthTable();
		BitSet XORNOTTruthTable = getXORNOTTruthTable();
				
		//Create the keys according to the specific gate.
		for (int gate = 0; gate < ungarbledGates.length; gate++) {
			//XOR gate
			if (ungarbledGates[gate].getTruthTable().equals(XORTruthTable)) {
				generateXORValues(ungarbledGates[gate], allWireValues, globalKeyOffset);
			//XORNOT gate
			} else if (ungarbledGates[gate].getTruthTable().equals(XORNOTTruthTable)) {
				generateXORNOTValues(ungarbledGates[gate], allWireValues, globalKeyOffset);
			//Standard gate
			}else {
				byte[] zeroValueBytes = new byte[keySize];
				prg.getPRGBytes(zeroValueBytes, 0, keySize);
				generateStandardValues(ungarbledGates[gate], allWireValues, globalKeyOffset, zeroValueBytes);
			}

		}
	}
	
	@Override
	public byte[] getHashedTables(BooleanCircuit ungarbledCircuit, PseudorandomGenerator prg, byte[] seed, CryptographicHash hash) throws InvalidKeyException {
			
  		Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
		
		// Calculate the garbled tables according to the given seed, then compute the hash function on the calculated tables.
  		sampleSeedKeys(ungarbledCircuit, prg, seed, allWireValues);
  		try {
			return computeHashOnTables(hash, allWireValues, ungarbledCircuit.getGates());
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (PlaintextTooLongException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
  		
  	}
  	
	/**
	 * Computes the hash function on the circuit's garbled tables.
	 * @param hash CryptographicHash function to use.
	 * @param allWireValues A map that contains both keys for each wire.
	 * @param ungarbledGates The gates of the ungarbled circuit
	 * @return the result of the hash function on the garbled tables.
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws PlaintextTooLongException
	 */
  	private byte[] computeHashOnTables(CryptographicHash hash, Map<Integer, SecretKey[]> allWireValues, Gate[] ungarbledGates) throws InvalidKeyException, IllegalBlockSizeException, PlaintextTooLongException {
		GarbledGate gate;
		
		// Get the XOR and XORNOT truth table to be used to test against for equality.
		BitSet XORTruthTable = getXORTruthTable();
		BitSet XORNOTTruthTable = getXORNOTTruthTable();
		int size =  ungarbledGates.length;
		
		byte[][] garbledTablesTemp = new byte[size][];
		GarbledTablesHolder temp = new GarbledTablesHolder(garbledTablesTemp);
		
		//For each Standard gate, create the garbled tables and update the hashed array with it.
		//After updating the hash, drop the garbled table. This way, no memory is saved. 
		for (int i = 0; i < size; i++) {
			if (!ungarbledGates[i].getTruthTable().equals(XORTruthTable) && !ungarbledGates[i].getTruthTable().equals(XORNOTTruthTable)) {
				gate = createStandardGate(ungarbledGates[i], temp);
				((StandardGarbledGate) gate).createGarbledTable(ungarbledGates[i], allWireValues);
				hash.update(garbledTablesTemp[i], 0, garbledTablesTemp[i].length);
				garbledTablesTemp[i] = null;
			}
		}
	
		//compute the hash function on the garbled tables.
		byte[] hashedTables = new byte[hash.getHashedMsgSize()];
		hash.hashFinal(hashedTables, 0);
		
		return hashedTables;
	}	

}
