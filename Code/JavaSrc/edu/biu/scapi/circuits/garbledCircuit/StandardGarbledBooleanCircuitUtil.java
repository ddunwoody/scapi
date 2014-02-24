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
import java.security.SecureRandom;
import java.util.ArrayList;
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
 * The {@StandardGarbledBooleanCircuitUtil} class is a utility class that computes the functionalities regarding Garbled Boolean Circuit
 * without optimizations (e.g. the Free XOR technique and row reduction technique etc. are not used).
 * 
 * @author Steven Goldfeder
 * 
 */

class StandardGarbledBooleanCircuitUtil implements CircuitTypeUtil{
	protected MultiKeyEncryptionScheme mes;
	protected SecureRandom random;
	
	/**
	 * Sets the given MultiKeyEncryptionScheme and random.
	 * @param mes
	 * @param random
	 */
	StandardGarbledBooleanCircuitUtil(MultiKeyEncryptionScheme mes, SecureRandom random){
		this.mes = mes;
		this.random = random;
	}
	
	/**
	 * Default constructor. Uses HashingMultiKeyEncryption and SecureRandom objects.
	 */
	StandardGarbledBooleanCircuitUtil(){
		this(new HashingMultiKeyEncryption(), new SecureRandom());
	}
	
	/**
	 * Creates the gates that matches StandardGarbledBooleanCircuit.
	 */
	public GarbledGate[] createGates(Gate[] ungarbledGates, GarbledTablesHolder garbledTablesHolder){
		GarbledGate[] gates = new GarbledGate[ungarbledGates.length];
	    int length = ungarbledGates.length;
		for (int gate = 0; gate < length; gate++) {
			gates[gate] = createGate(ungarbledGates[gate], garbledTablesHolder);
		}
		return gates;
	}

	/**
	 * Creates a StandardGarbledGate.
	 * @param ungarbledGate to garble.
	 * @param garbledTablesHolder
	 * @return the created gate.
	 */
	protected GarbledGate createGate(Gate ungarbledGate, GarbledTablesHolder garbledTablesHolder) {
		return new StandardGarbledGate(ungarbledGate, mes, garbledTablesHolder);
	}
	
	@Override
  	public CircuitCreationValues garble(BooleanCircuit ungarbledCircuit, GarbledTablesHolder garbledTablesHolder, 
			GarbledGate[] gates) {
		Map<Integer, SecretKey[]> emptyWireValues = new HashMap<Integer, SecretKey[]>();
		
		//Call the other garble function, when the partialWireValues is empty (i.e no partial keys). 
		return garble(ungarbledCircuit, garbledTablesHolder, gates, emptyWireValues);
	}
	
	@Override
	public CircuitCreationValues garble(BooleanCircuit ungarbledCircuit, GarbledTablesHolder garbledTablesHolder, 
			GarbledGate[] gates, Map<Integer, SecretKey[]> partialWireValues) {
		
		//Prepare the maps that will be used during keys generation.
		Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
		Map<Integer, SecretKey[]> allInputWireValues = null;
		Map<Integer, SecretKey[]> allOutputWireValues = null;
		HashMap<Integer, Byte> translationTable = new HashMap<Integer, Byte>();
		Gate[] ungarbledGates = ungarbledCircuit.getGates();
		
		//If there are partial keys, check if they are the input keys or the output keys and set them.
		if (!partialWireValues.isEmpty()){
			allWireValues.putAll(partialWireValues);
			
			if (partialWireValues.containsKey(ungarbledCircuit.getOutputWireLabels()[0])){
				allOutputWireValues = partialWireValues;
				//Generate the translation table out of the given output keys.
				for (int n : ungarbledCircuit.getOutputWireLabels()) {
					//Signal bit is the last bit of k0.
					byte[] k0 = allWireValues.get(n)[0].getEncoded();
					translationTable.put(n, (byte) (k0[k0.length-1] & 1));	
				}
			} else{
				allInputWireValues = partialWireValues;
			}
		} 
		
		//In case the keys for the input wires have not been sampled yet, sample them.
		if (allInputWireValues == null){
			allInputWireValues = new HashMap<Integer, SecretKey[]>();
			for (int i=1; i<=ungarbledCircuit.getNumberOfParties(); i++){
				ArrayList<Integer> inputWireLabels = null;
				try {
					inputWireLabels = ungarbledCircuit.getInputWireLabels(i);
				} catch (NoSuchPartyException e) {
					// should not occur since the number is a valid party number
				}
				for (int w : inputWireLabels) {
					sampleStandardKeys(allInputWireValues, w);
				}
			}
			allWireValues.putAll(allInputWireValues);
		}
		
		//for each gate fill the keys and signal bits for output wires if they are not filled yet.
		for (int gate = 0; gate < ungarbledGates.length; gate++) {
			generateOutputKeys(allOutputWireValues, ungarbledGates[gate], allWireValues);
		}
		
		//In case the keys for the output wires have not been sampled yet, fill them.
		if (allOutputWireValues == null){
			allOutputWireValues = new HashMap<Integer, SecretKey[]>();
			fillOutputWiresValues(ungarbledCircuit.getOutputWireLabels(), allOutputWireValues, allWireValues, translationTable);
		}
		
		//After we have all keys, create the garbledTables according to them.
		try {
			createGarbledTables(gates, garbledTablesHolder, ungarbledGates, allWireValues);
		} catch (InvalidKeyException e) {
			//  Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
		} catch (IllegalBlockSizeException e) {
			// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
		} catch (PlaintextTooLongException e) {
			// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
		}
		
		return new CircuitCreationValues(allInputWireValues, allOutputWireValues, translationTable);
	}
	
	/**
	 * Samples the keys for the output wires of the given gate.
	 * @param allOutputWireValues both keys of all output wires.
	 * @param ungarbledGate the gate we should sample keys for its output wires.
	 * @param allWireValues a map to fill with the wires' keys.
	 */
	protected void generateOutputKeys(Map<Integer, SecretKey[]> allOutputWireValues, Gate ungarbledGate, Map<Integer, SecretKey[]> allWireValues) {
		// In case there are no output keys filled yet, create all output keys.
		if (allOutputWireValues == null){
			int len = ungarbledGate.getOutputWireLabels().length;
			for (int i = 0; i < len; i++) {
				int wireLabel = ungarbledGate.getOutputWireLabels()[i];
				sampleStandardKeys(allWireValues, wireLabel);
			}
		//In case there are output keys, sample only keys that missing.
		} else{
			int len = ungarbledGate.getOutputWireLabels().length;
			for (int i = 0; i < len; i++) {
				int wireLabel = ungarbledGate.getOutputWireLabels()[i];
				if (!allOutputWireValues.containsKey(wireLabel)){
					sampleStandardKeys(allWireValues, wireLabel);
				}
			}
		}
		
	}
	
	/**
	 * Creates the garbled tables. This is done by the constructor of the gates.
	 * @param gates array of gates to fill.
	 * @param garbledTablesHolder holds the garbled tables.
	 * @param ungarbledGates the gates that need to be garbled.
	 * @param allWireValues a map that contains both keys for each wire.
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws PlaintextTooLongException
	 */
	private void createGarbledTables(GarbledGate[] gates, GarbledTablesHolder garbledTablesHolder, Gate[] ungarbledGates, Map<Integer, SecretKey[]> allWireValues) throws InvalidKeyException, IllegalBlockSizeException, PlaintextTooLongException {
		int length = ungarbledGates.length;
		//After we have all keys, create the garbledTables according to them.
		for (int gate = 0; gate < length; gate++) {
			((StandardGarbledGate) gates[gate]).createGarbledTable(ungarbledGates[gate], allWireValues);
		}
	}

	/**
	 * Fills the maps containing the keys for the output wires and the translation table.
	 * @param outputWireLabels labels of output wires.
	 * @param allOutputWireValues a map to fill with the output wires' keys.
	 * @param allWireValues a map to take the output wires' keys from.
	 * @param translationTable a map to fill with the output wires' signal bits.
	 */
	private void fillOutputWiresValues(int[] outputWireLabels, Map<Integer, SecretKey[]> allOutputWireValues, Map<Integer, SecretKey[]> allWireValues,
			Map<Integer, Byte> translationTable) {
		/*
		 * Add the output wire labels' signal bits to the translation table. For a full understanding on why we chose to 
		 * implement the translation table this way, see the documentation to the translationTable field of
		 * GarbledBooleanCircuitImp.
		 */
		for (int n : outputWireLabels) {
			//Signal bit is the last bit of k0.
			byte[] k0 = allWireValues.get(n)[0].getEncoded();
			translationTable.put(n, (byte) (k0[k0.length-1] & 1));	
			
			//Add both values of output wire to the allOutputWireValues Map that was passed as a parameter.
			allOutputWireValues.put(n, allWireValues.get(n));
		}
	}

	/**
	 * Samples both keys of the given wire's label.
	 * @param allWireValues a map that contains both keys for each wire.
	 * @param wireLabel the label of the wire we want to sample keys for.
	 */
	private void sampleStandardKeys(Map<Integer, SecretKey[]> allWireValues, int wireLabel) {
		
		//Sample a 0-encoded value and a 1-encoded value for each GarbledWire.
		SecretKey zeroValue = mes.generateKey();
		SecretKey oneValue = mes.generateKey();
		
		adjustKeysToSignalBit(allWireValues, wireLabel, zeroValue.getEncoded(), oneValue.getEncoded());
		
	}

	private void adjustKeysToSignalBit(Map<Integer, SecretKey[]> allWireValues,	int wireLabel, byte[] zeroBytes, byte[] oneBytes) {
		
		SecretKey zero = null, one = null;
		if ((zeroBytes[zeroBytes.length - 1] & 1) == 0) {
			// Set the 1-value signal bit. This is the last bit of the wire's 1 value(key).
			oneBytes[oneBytes.length - 1] |= 1;
		} else{
			// Set the 1-value signal bit. This is the last bit of the wire's 1 value(key).
			oneBytes[oneBytes.length - 1] &= 254;
		}
		zero = new SecretKeySpec(zeroBytes, "");
		one = new SecretKeySpec(oneBytes, "");
		
		// Put the 0-value and the 1-value on the allWireValuesMap.
		SecretKey[] keys = new SecretKey[] {zero, one};
		allWireValues.put(wireLabel, keys);
	}
	
	@Override
	public CircuitSeedCreationValues garble(BooleanCircuit ungarbledCircuit, GarbledTablesHolder garbledTablesHolder, 
			GarbledGate[] gates, PseudorandomGenerator prg, byte[] seed, CryptographicHash hash) throws InvalidKeyException {
		
		Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
		Gate[] ungarbledGates = ungarbledCircuit.getGates();
		
		//Call the function that sample the keys.
		CircuitCreationValues values = sampleSeedKeys(prg, seed, ungarbledCircuit, allWireValues);
				
		//Now that all wires have garbled values, we create the garbled tables.
		byte[][] garbledTables = garbledTablesHolder.getGarbledTables();
			
		byte[] hashedCircuit = null;
		try {
			//Create each gate, and update the hash array with the created garbled table.
			for (int gate = 0; gate < gates.length; gate++) {
				((StandardGarbledGate) gates[gate]).createGarbledTable(ungarbledGates[gate], allWireValues);
				hash.update(garbledTables[gate], 0, garbledTables[gate].length);
			}
			hashedCircuit = new byte[hash.getHashedMsgSize()];
			hash.hashFinal(hashedCircuit, 0);
				
		
		} catch (PlaintextTooLongException e) {
			// Should not occur since the plaintext length is valid.
		} catch (IllegalBlockSizeException e) {
			// Should not occur since the block size is valid.
		} 
				
		return new CircuitSeedCreationValues(values.getAllInputWireValues(), values.getAllOutputWireValues(), values.getTranslationTable(), hashedCircuit);
	}
	
	/**
	 * Samples the keys.
	 * @param prg used to sample values
	 * @param seed used to initialize the prg
	 * @param ungarbledCircuit the circuit that this garbled circuit should be the garbled of.
	 * @param allWireValues a map that contains both keys for each wire.
	 * @return the values sampled by the function
	 * @throws InvalidKeyException
	 */
	private CircuitCreationValues sampleSeedKeys(PseudorandomGenerator prg, byte[] seed, BooleanCircuit ungarbledCircuit, 
			Map<Integer, SecretKey[]> allWireValues) throws InvalidKeyException{
		Map<Integer, SecretKey[]> allInputWireValues = new HashMap<Integer, SecretKey[]>();
		Map<Integer, SecretKey[]> allOutputWireValues = new HashMap<Integer, SecretKey[]>();
		HashMap<Integer, Byte> translationTable = new HashMap<Integer, Byte>();
		
		//Sets the given seed as the prg key.
		prg.setKey(new SecretKeySpec(seed, ""));
		
		//Create both keys for all input wires.
		for (int i=1; i<=ungarbledCircuit.getNumberOfParties(); i++){
			ArrayList<Integer> inputWireLabels = null;
			try {
				inputWireLabels = ungarbledCircuit.getInputWireLabels(i);
			} catch (NoSuchPartyException e) {
				// should not occur since the number is a valid party number
			}
			for (int w : inputWireLabels) {
				sampleKeysFromSeed(allInputWireValues, w, prg);
			}
		}
		
		//Set the keys of the input wires. 
		allWireValues.putAll(allInputWireValues);
		
		Gate[] ungarbledGates = ungarbledCircuit.getGates();
		
		//for each gate fill the keys and signal bits for output wires.
		for (int gate = 0; gate < ungarbledGates.length; gate++) {
			generateOutputKeysFromSeed(prg, allWireValues, ungarbledGates[gate]);
		}
		
		fillOutputWiresValues(ungarbledCircuit.getOutputWireLabels(), allOutputWireValues, allWireValues, translationTable);
		
		return new CircuitCreationValues(allInputWireValues, allOutputWireValues, translationTable);
	}

	/**
	 * Samples the output keys by the prg and seed.
	 * @param prg 
	 * @param allWireValues a map that contains both keys for each wire.
	 * @param ungarbledGate the gate we want to sample keys for its output wires.
	 */
	protected void generateOutputKeysFromSeed(PseudorandomGenerator prg,Map<Integer, SecretKey[]> allWireValues, Gate ungarbledGate) {
		//Get the labels of the output wires.
		int[] labels = ungarbledGate.getOutputWireLabels();
		int len = labels.length;
		//Sample keys for each label.
		for (int i = 0; i < len; i++) {
			int wireLabel = labels[i];
			sampleKeysFromSeed(allWireValues, wireLabel, prg);
		}
	}
	
	/**
	 * Samples both keys of the given wire's label using the Prg.
	 * @param allWireValues a map that contains both keys for each wire.
	 * @param wireLabel the label of the wire we need to sample keys for.
	 * @param prg 
	 */
	private void sampleKeysFromSeed(Map<Integer, SecretKey[]> allWireValues, int wireLabel,	PseudorandomGenerator prg) {
		
		//Assign a 0-encoded value and a 1-encoded value for each GarbledWire.
		int keySize = mes.getCipherSize();
		byte[] zeroKeyBytes = new byte[keySize];
		byte[] oneKeyBytes = new byte[keySize];
		prg.getPRGBytes(zeroKeyBytes, 0, keySize);
		prg.getPRGBytes(oneKeyBytes, 0, keySize);
		
		adjustKeysToSignalBit(allWireValues, wireLabel, zeroKeyBytes, oneKeyBytes);
		
	}

	@Override
	public byte[] getHashedTables(BooleanCircuit ungarbledCircuit, PseudorandomGenerator prg, byte[] seed, CryptographicHash hash) throws InvalidKeyException {
		
		Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
		
		//Calculate the garbled tables according to the given seed, then compute the hash function on the calculated tables.
		sampleSeedKeys(prg, seed, ungarbledCircuit, allWireValues);
		
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
	 * @param hash CryptographicHash function to use
	 *  @param allWireValues a map that contains both keys for each wire.
	 * @param ungarbledGates the gates of the ungarbled circuit
	 * @return the result of the hash function on the garbled tables.
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws PlaintextTooLongException
	 */
	private byte[] computeHashOnTables(CryptographicHash hash,Map<Integer, SecretKey[]> allWireValues, Gate[] ungarbledGates)
			throws InvalidKeyException, IllegalBlockSizeException, PlaintextTooLongException {
		GarbledGate gate;
		int size =  ungarbledGates.length;
		
		byte[][] garbledTablesTemp = new byte[size][];
		GarbledTablesHolder temp = new GarbledTablesHolder(garbledTablesTemp);
		
		//For each gate, create the garbled tables and update the hashed array with it.
		//After updating the hash, drop the garbled table. This way, no memory is saved.
		for (int i = 0; i < size; i++) {
			gate = createGate(ungarbledGates[i], temp);
			((StandardGarbledGate) gate).createGarbledTable(ungarbledGates[i], allWireValues);
			hash.update(garbledTablesTemp[i], 0, garbledTablesTemp[i].length);
			garbledTablesTemp[i] = null;
		}
		
		//compute the hash function on the garbled tables.
		byte[] hashedCircuit = new byte[hash.getHashedMsgSize()];
		hash.hashFinal(hashedCircuit, 0);
		
		return hashedCircuit;
	}
}
