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
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.circuit.Gate;
import edu.biu.scapi.circuits.circuit.Wire;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CiphertextTooLongException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;
import edu.biu.scapi.exceptions.PlaintextTooLongException;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.prg.PseudorandomGenerator;

/**
 * This class is an implementation of an extended garbled boolean circuit.<p>
 * 
 * The extensions implemented in this class are:<P>
 * 1. The ability to set the input or/and output garbled values.<p>
 * 2. The ability to sample the garbled values using a given seed.<p>
 * 1. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class GarbledBooleanCircuitExtendedImp implements GarbledBooleanCircuitExtended {
	
	/*
	 * In order to allow garbling with fixed input or output keys we decided to add an identity gate for each input and output wire.
	 * The additional gates will be added only if the user actually set the garbled values.
	 * Meaning, if there are 128 input wires and 128 output wires, and the user set their garbled values, our GarbledBooleanCircuitFixedKeys 
	 * will have 256 more gates.
	 * This way, if the user gave input or output wires' values it does not relevant to the inner GarbledBooleanCircuit. It will generate 
	 * all keys randomly. The identity gates will map the given input/output keys to the generated ones.
	 * 
	 * Important note: when garbling or setting input values, we need to adjust the wires indices regarding the new gates and wires.
	 * For example, if the user set input keys, for each wire i there are additional input gate with input wire -(i+1) and output wire i.
	 * Thus, when the user want to set an input for wire i, actually we need to set the input to wire -(i+1).		
	 */
	
	
	private GarbledBooleanCircuitAbs gbc; 		// The underlying circuit to use.
	private PseudorandomGenerator prg;			// The prg to use when garbling using a seed.
	private MultiKeyEncryptionScheme mes;		// The underlying encryption scheme to use when garbling using an encryption.
	private IdentityGate[] inputIdentityGates;	// The array of input gates in case the user set the input garbled values.
	private IdentityGate[] outputIdentityGates;	// The array of output gates in case the user set the input garbled values.
	
	/*
  	 * Holds the garbled tables of this garbled circuit. This is stored in the garbled circuit and also in the gates. 
  	 * We keep the garbled tables that way because when sending the circuit to a different party it is sufficient to send only 
  	 * the garbled tables and translation table, if needed. 
  	 * The party who receives the tables only needs to change the pointer in the holder class to the received tables.
  	 * 
  	 * We store the garbled tables in a two dimensional array, the first dimension for each gate and the other dimension for the encryptions.
  	 * Each table of each gate is a one dimensional array of bytes rather than an array of ciphertexts. 
  	 * This is for time/space efficiency reasons: If a single garbled table is an array of ciphertext that holds a byte array the space
  	 * stored by java is big. The main array holds references for each item (4 bytes). Each array in java has an overhead of 12 bytes. 
  	 * Thus the garbled table with ciphertexts has at least (12+4)*number of rows overhead.
  	 * If we store the array as one dimensional array we only have 12 bytes overhead for the entire table and thus this is the way we 
  	 * store the garbled tables. 
  	 */
  	private ExtendedGarbledTablesHolder garbledTablesHolder;
  	
    // A map that is used during computation to map a {@code GarbledWire}'s index to the computed and set {@code GarbledWire}.
  	private Map<Integer, GarbledWire> computedWires = new HashMap<Integer,GarbledWire>();

  	private ArrayList<Integer> inputIndices;	// Holds the input wires' indices.
  	private int[] outputIndices;				// Holds the output wires' indices.
  	
  	private Map<Integer, SecretKey[]> inputGarbledValues;	//Holds the input garbled values given from the user.
  	private Map<Integer, SecretKey[]> outputGarbledValues;	//Holds the output garbled values given from the user.
  	
  	// We save the output from the inner circuit because we use it in the translate function:
  	// Translate function uses the signal bit format in order to translate, but in case the user set the output garbled values,
  	// the values not necessarily are in that format. Because the output from the compute function (that will be sent to the translate function)
  	// will be the values from the user, we save the output from the inner circuit and use them in order to get the signal bit and do the translate.
  	private HashMap<Integer, GarbledWire> outputFromInnerCircuit;	
  	
  	/**
  	 * This constructor should be used in case the garbling is done using a MultiKeyEncryptionScheme.<P>
  	 * It gets the inner garbled boolean circuit and the encryption scheme.
  	 * @param gbc The inner garbled boolean circuit to wrap.
  	 * @param mes The MultiKeyEncryptionScheme to use during garbling.
  	 */
	public GarbledBooleanCircuitExtendedImp(GarbledBooleanCircuit gbc, MultiKeyEncryptionScheme mes) {
		if (!(gbc instanceof GarbledBooleanCircuitAbs)){
			throw new IllegalArgumentException("the given gbc should be an instance of GarbledBooleanCircuitAbs");
		}
		this.gbc = (GarbledBooleanCircuitAbs) gbc;
		this.mes = mes;
		
		//Input and output indices will be needed multiple times, we hold them as class members to avoid the creation of the arrays each time they needed.
		outputIndices = gbc.getOutputWireIndices();
		inputIndices = new ArrayList<Integer>();
		for (int i=1; i <= gbc.getNumberOfParties(); i++){
			
			try {
				inputIndices.addAll(getInputWireIndices(i));
			} catch (NoSuchPartyException e) {
				// Should not occur since the party number is between 1 to bc.getNumberOfParties()
			}
		}
					
		//Create the garbled tables holder with holders for the identity gates and the inner circuit.
		BasicGarbledTablesHolder inputGarbledTables = new BasicGarbledTablesHolder(null);
		BasicGarbledTablesHolder outputGarbledTables = new BasicGarbledTablesHolder(null);
		garbledTablesHolder = new ExtendedGarbledTablesHolder(inputGarbledTables, outputGarbledTables, gbc.getGarbledTables());
	}
	
	/**
  	 * This constructor should be used in case the garbling is done using a PRG and seed.<P>
  	 * It gets the inner garbled boolean circuit, the encryption scheme and the PRG.
  	 * @param gbc The inner {@link GarbledBooleanCircuit} to wrap.
  	 * @param mes The {@link MultiKeyEncryptionScheme} to use during garbling.
  	 * @param prg The {@link PseudorandomGenerator} to use during the garbling process.
  	 */
	public GarbledBooleanCircuitExtendedImp(GarbledBooleanCircuit gbc, MultiKeyEncryptionScheme mes, PseudorandomGenerator prg) {
		
		this(gbc, mes);
		this.prg = prg;
	}
	
	@Override
	public void setInputKeys(Map<Integer, SecretKey[]> inputValues){
		this.inputGarbledValues = adjustIndices(inputValues);
	}
	
	@Override
	public void setOutputKeys(Map<Integer, SecretKey[]> outputValues){
		this.outputGarbledValues = adjustIndices(outputValues);
	}
	
	@Override
	public CircuitCreationValues garble() {
		//Call the inner circuit's garble function to generate its keys.
		CircuitCreationValues values = gbc.garble();
		//Generate the input and output gates, if needed.
		return generateInputOutputGates(values);
	}
	
	@Override
	public CircuitCreationValues garble(byte[] seed) throws InvalidKeyException {
		// In order to garble using seed, we need two seeds: one for the inner circuit and one for the extended.
		// Use the given seed in order to generate two new seeds.
		
		//Set the given seed as the prg's key.
		prg.setKey(new SecretKeySpec(seed, ""));
		
		//use the prg to generate two seeds.
		byte[] out = new byte[seed.length*2];
		prg.getPRGBytes(out, 0, out.length);
		
		//Create new seeds.
		byte[] innerSeed = new byte[seed.length];
		byte[] extendedSeed = new byte[seed.length];
		System.arraycopy(out, 0, innerSeed, 0, seed.length);
		System.arraycopy(out, seed.length, extendedSeed, 0, seed.length);
		
		//Garble the inner circuit using the inner seed.
		CircuitCreationValues values = gbc.garble(innerSeed);
		
		//Set the extended seed as the prg's key. It will be used in the identity gates.
		prg.setKey(new SecretKeySpec(extendedSeed, ""));
		//Generate the input and output gates, if needed.
		return generateInputOutputGates(values);
	}

	/**
	 * In case the user set input and/or output keys, create the corresponding gates.<P>
	 * The algorithm to add the gates:<P>
	 *	1. For each input wire i, add a gate with input wire -(i+1) and the output wire i. <P>
	 *	2. For each output wire i, add a gate with input wire i and the output wire -(i+1). <P>
	 *	
	 * @param values The values returned from the inner circuit's garble function.
	 * @return The input and output keys of this circuit, along with the translation table of the inner circuit. 
	 */
	private CircuitCreationValues generateInputOutputGates(CircuitCreationValues values) {
		
		//Create a map that holds all the garbled values.
		Map<Integer, SecretKey[]> allValues = new HashMap<Integer, SecretKey[]>();
		//Put in the map the input and output keys of the inner circuit.
		allValues.putAll(values.getAllInputWireValues());
		allValues.putAll(values.getAllOutputWireValues());
		
		//In case the user set the input keys, create the input identity gates.
		if (inputGarbledValues != null){
			//Put the input keys in the keys array.
			allValues.putAll(inputGarbledValues);
			
			int size = inputIndices.size();
			//Set an empty garbled tables array in the right size.
			garbledTablesHolder.getInputGarbledTables().setGarbledTables(new byte[size][]);
			createInputIdentityGates(size);
		} else{
			inputGarbledValues = values.getAllInputWireValues();
		}
		
		//In case the user set the output keys, create the output identity gates.
		if (outputGarbledValues != null){
			//Put the output keys in the keys array.
			allValues.putAll(outputGarbledValues);
			
			int size = outputIndices.length;
			//Set an empty garbled tables array in the right size.
			garbledTablesHolder.getOutputGarbledTables().setGarbledTables(new byte[size][]);
			createOutputIdentityGates(size);
		} else{
			outputGarbledValues = values.getAllOutputWireValues();
		}
		
		
		//After we have all keys, create the garbledTables according to them.
		try {
			createGarbledTables(allValues);
		} catch (InvalidKeyException e) {
			//  Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
		} catch (IllegalBlockSizeException e) {
			// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
		} catch (PlaintextTooLongException e) {
			// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
		}
		
		//Return the input and output keys of this circuit, along with the translation table of the inner circuit. 
		return new CircuitCreationValues(inputGarbledValues, outputGarbledValues, values.getTranslationTable());
	}
	
	/**
	 * Adjusts the indices to the new indices after adding the identity gates.<P>
	 * When garbling or setting input values, we need to adjust the wires indices regarding the new gates and wires.<P>
	 * For example, if the user set input keys, for each wire i there are additional input gate with input wire -(i+1) and output wire i.
	 * Thus, when the user want to set an input for wire i, actually we need to set the input to wire -(i+1).		
	 * @param partialWireValues A map containing for each wireIndex the keys. The indices in the map should be adjusted.
	 * @return The same map with the adjusted indices.
	 */
	private Map<Integer, SecretKey[]> adjustIndices(Map<Integer, SecretKey[]> partialWireValues) {
		HashMap<Integer, SecretKey[]> adjusted = new HashMap<Integer, SecretKey[]>();
		
		//for each index i in the given map, put in the adjusted map the keys with index -(i+1).
		Object[] keys = partialWireValues.keySet().toArray();
		for (Object key : keys){
			int keyI = (Integer) key;
			
			adjusted.put((keyI+1)*(-1), partialWireValues.get(key));
		}
		
		return adjusted;
	}

	/**
	 * Creates the garbled tables of the identity gates. 
	 * @param allWireValues A map that contains both keys for each wire.
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws PlaintextTooLongException
	 */
	protected void createGarbledTables(Map<Integer, SecretKey[]> allWireValues) throws InvalidKeyException, IllegalBlockSizeException, PlaintextTooLongException {
		//After we have all keys, create the garbledTables according to them.
		if (inputIdentityGates != null){
			//Create garbled tables for each input identity gate.
			for (IdentityGate gate : inputIdentityGates ) {
				gate.createGarbledTable(allWireValues);
			}
			//Return the indices to the original form (as the user gave them).
			inputGarbledValues = adjustIndices(inputGarbledValues);
		}
		
		if (outputIdentityGates != null){
			//Create garbled tables for each output identity gate.
			for (IdentityGate gate : outputIdentityGates ) {
				gate.createGarbledTable(allWireValues);
			}
			//Return the indices to the original form (as the user gave them).
			outputGarbledValues = adjustIndices(outputGarbledValues);
		}
	}
  
	@Override
 	public void setGarbledInputFromUngarbledInput(Map<Integer, Byte> ungarbledInput, Map<Integer, SecretKey[]> allInputWireValues) {
  		
  		Map<Integer, GarbledWire> inputs = new HashMap<Integer, GarbledWire>();
  		Set<Integer> keys = ungarbledInput.keySet();
  		
  		//For each wire, fill the map with wire number and garbled input.
  		for (Integer wireNumber : keys) {
  			inputs.put(wireNumber, new GarbledWire(allInputWireValues.get(wireNumber)[ungarbledInput.get(wireNumber)]));
  		}
  		setInputs(inputs);
  	}
	
  	@Override
  	public void setInputs(Map<Integer, GarbledWire> presetInputWires) {
  		
  		Map<Integer, GarbledWire> adjustedInputWires;
  		//In case there are identity gates, the indices should be adjusted.
  		if (inputIdentityGates != null){
  			adjustedInputWires = new HashMap<Integer, GarbledWire> ();
	  		for (Object key : presetInputWires.keySet().toArray()){
	  			adjustedInputWires.put(((Integer)key+1)*(-1), presetInputWires.get(key));
	  		}
	  	} else{
  			adjustedInputWires = presetInputWires;
  		}
  		
  		//Set the input garbled values in the map that holds the computes values of each wire.
  		computedWires.putAll(adjustedInputWires);
  	    
 	}
 
  	@Override
  	public HashMap<Integer, GarbledWire> compute() throws NotAllInputsSetException{
  		//check that all the input has been set.
  		for (int i=1; i <= getNumberOfParties(); i++){
  			//Get the wire numbers of the current party.
  			List<Integer> wireNumbers = null;
			try {
				wireNumbers = getInputWireIndices(i);
				//In case there are identity gates, the numbers should be adjusted.
				if (inputIdentityGates != null){
					List<Integer> temp = new ArrayList<Integer>();
					for (int j=0; j < wireNumbers.size(); j++){
						temp.add((-1)*(wireNumbers.get(j) + 1));
					}
					wireNumbers = temp;
				}
			} catch (NoSuchPartyException e) {
				// Should not occur since the parties numbers are between 1 to getNumberOfParties.
			}
  			
	  		for (int wireNumber : wireNumbers){
	  			if (!computedWires.containsKey(wireNumber)) {
	  				throw new NotAllInputsSetException();
	  			}
	  		}
  		}
  		
  		//If there are input identity gates, compute each one of them.
  		if (inputIdentityGates != null){
	  		for (IdentityGate g : inputIdentityGates) {
	  			try {
					g.compute(computedWires);
				} catch (InvalidKeyException e) {
					// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
				} catch (IllegalBlockSizeException e) {
					// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
				} catch (CiphertextTooLongException e) {
					// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
				}
	  		}
  		}
  		
  		//Set the input of the inner circuit (which has been calculated as the output of the input identity gates).
  		gbc.setInputs(computedWires);
  		//Compute the inner circuit.
  		outputFromInnerCircuit = gbc.compute();
  		
  		//If there are output identity gates, compute each one of them.
  		if (outputIdentityGates != null){
	  		for (IdentityGate g : outputIdentityGates) {
	  			try {
					g.compute(outputFromInnerCircuit);
				} catch (InvalidKeyException e) {
					// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
				} catch (IllegalBlockSizeException e) {
					// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
				} catch (CiphertextTooLongException e) {
					// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
				}
	  		}
  		}
		
  		//Copy only the values that we need to retain -- i.e. the values of the output wires to a new map to be returned. 
  		//If there are output identity gates, the wire indexes should be adjusted.
  		HashMap<Integer, GarbledWire> garbledOutput = new HashMap<Integer, GarbledWire>();
  		if (outputIdentityGates != null){
	  		for (int w : gbc.getOutputWireIndices()) {
	  			garbledOutput.put(w, outputFromInnerCircuit.get(-1*(w+1)));
	  		}
  		} else{
  			garbledOutput = outputFromInnerCircuit;
  		}

  		return garbledOutput;
  	}	

  	@Override
  	public boolean verify(Map<Integer, SecretKey[]> allInputWireValues) {
  		
  		Map<Integer, SecretKey[]> internalOutputs = new HashMap<Integer, SecretKey[]>();  
  		Map<Integer, SecretKey[]> extendedOutputs = new HashMap<Integer, SecretKey[]>();  
  		
  		//Call a function that verifies the circuit without verifying the translation table.
  		//The function fills the internal and extended output maps.
  		boolean verified = verifyCircuitReturnOutputs(allInputWireValues, internalOutputs, extendedOutputs);
  		if (verified == false){
  			return false;
  		}
  		
  		//Verify the translation table using the output from the inner circuit.
  		return verifyTranslationTable(internalOutputs);
  	}
  	
  	@Override
	public boolean verify(Map<Integer, SecretKey[]> allInputWireValues, Map<Integer, SecretKey[]> allOutputWireValues){

  		Map<Integer, SecretKey[]> internalOutputs = new HashMap<Integer, SecretKey[]>();  
  		Map<Integer, SecretKey[]> extendedOutputs = new HashMap<Integer, SecretKey[]>();  
		
  		//Call a function that verifies the circuit without verifying the translation table.
  		//The function fills the internal and extended output maps.
  		boolean verified = verifyCircuitReturnOutputs(allInputWireValues, internalOutputs, extendedOutputs);
  		
  		//Verify the translation table using the output from the inner circuit.
  		verified = verified && verifyTranslationTable(internalOutputs);
		
  		//Verify the generated output values with the given output values.
		if (outputIdentityGates != null){
			for (int w : gbc.getOutputWireIndices()) {
				verified = verified && checkEquality(extendedOutputs.get(w), allOutputWireValues.get(w));
	  		}
		}
  		return verified;
  	}
  	
  	@Override
	public boolean internalVerify(Map<Integer, SecretKey[]> allInputWireValues, Map<Integer, SecretKey[]> allOutputWireValues) {
  		
		Map<Integer, SecretKey[]> internalOutputs = new HashMap<Integer, SecretKey[]>();  
  		Map<Integer, SecretKey[]> extendedOutputs = new HashMap<Integer, SecretKey[]>();  
  		
  		//Call a function that verifies the circuit without verifying the translation table.
  		//The function fills the internal and extended output maps.
  		boolean verified = verifyCircuitReturnOutputs(allInputWireValues, internalOutputs, extendedOutputs);
  		
  		//This function should return the output keys of the circuit.
  		//In case the circuit does not contain output identity gates, the output keys are the same as the output from the inner circuit.
		if (outputIdentityGates == null){
			allOutputWireValues.putAll(internalOutputs);
		//In case the circuit does contain output identity gates, the output keys are the output of the extended circuit.
		} else {
			allOutputWireValues.putAll(extendedOutputs);
		}
		
		return verified;
	}
  	
  	
  	/**
  	 * Check that the output wires translate correctly. 
  	 * @param internalOutputs
  	 * @return
  	 */
	private boolean verifyTranslationTable(Map<Integer, SecretKey[]> keys) {
		//Check that the output wires translate correctly. 
	    //key contains both possible values for every output wire of the inner circuit. 
		//We check the output wire values and make sure that the 0-wire translates to a 0 and that the 1 wire translates to a 1.
  		Map<Integer, Byte> translationTable = gbc.getTranslationTable();
  		SecretKey zeroValue, oneValue;
  		byte signalBit, permutationBitOnZeroWire, permutationBitOnOneWire, translatedZeroValue, translatedOneValue;
  		
  		for (int w : gbc.getOutputWireIndices()) {
  			zeroValue = keys.get(w)[0];
  			oneValue = keys.get(w)[1];

  			signalBit = translationTable.get(w);
  			permutationBitOnZeroWire = gbc.getKeySignalBit(zeroValue);
  			permutationBitOnOneWire = gbc.getKeySignalBit(oneValue);;
  			translatedZeroValue = (byte) (signalBit ^ permutationBitOnZeroWire);
  			translatedOneValue = (byte) (signalBit ^ permutationBitOnOneWire);
  			if (translatedZeroValue != 0 || translatedOneValue != 1) {
  				return false;
  			}
  		}
  		return true;
	}
  	
  	/**
  	 * Verifies that this circuit is the garbling of the given input garbled values. <P>
  	 * During the execution, fill the given internalOutputs array with the outputs garbled values of the internal circuit,
  	 * and the extendedOutputs array with the outputs garbled values of the extended circuit.<p>
  	 * @param allInputWireValues A {@Map} containing both keys for each input wire. 
  	 * @param internalOutputs An empty array that will be filled with the output garbled values of the internal circuit.
  	 * @param extendedOutputs An empty array that will be filled with the output garbled values of the extended circuit.
  	 * @return true if the circuit is verified; False, otherwise.
  	 */
	private boolean verifyCircuitReturnOutputs(Map<Integer, SecretKey[]> allInputWireValues, Map<Integer, SecretKey[]> internalOutputs,
			Map<Integer, SecretKey[]> extendedOutputs) {
		
		// We are going to need to add values for non-input wires to the map as we compute them (this will take place in the Gate's 
		// verify method that we are about to call). In order to not change the input Map, we first copy its contents to a new Map.
		Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();  
		
		//If there are input identity gates, adjust the given input wires indexes.
		if (inputIdentityGates != null){
			for (Object key: allInputWireValues.keySet().toArray()){
				allWireValues.put(((Integer)key+1)*-1, allInputWireValues.get(key));
			}
		} else{
			allWireValues.putAll(allInputWireValues);
		}
		
		//Verify the input identity gates.
		if (inputIdentityGates != null && !verifyInputs(inputIndices, allWireValues)){
			return false;
		}
		
		//Verify the inner circuit without the translation table.
		if (!(gbc.internalVerify(allWireValues, internalOutputs))){
			return false;
		}
		//Set the output from the internal verify.
		allWireValues.putAll(internalOutputs);
		
		//Verify the output identity gates.
		if (outputIdentityGates != null && !verifyOutputs(allWireValues)){
			return false;
		} 
		
		//Fill the output values of the extended output.
		if (outputIdentityGates != null){
			for (int w : gbc.getOutputWireIndices()) {
				extendedOutputs.put(w, allWireValues.get(-1*(w+1)));
			}
		}
		return true;
	}
  	

	@Override
	public boolean verify(byte[] seed, Map<Integer, SecretKey[]> allInputGarbledValues,
			Map<Integer, SecretKey[]> allOutputGarbledValues, CryptographicHash hash, byte[] hashedCircuit) throws InvalidKeyException {
		
		//Verify using a seed verifies that if you create a circuit using the given seed, the output garbled tables and translation table is correct.
		//This is done by computing a hash function on the garlbed tables and translation table and comparing it to the given hashedCircuit.
		
		//In case this circuit has no garbled tables yet, garble it to create the tables.
		if (garbledTablesHolder.getInternalGarbledTables().toDoubleByteArray() == null){
			//Set the input keys if there are.
			if (allInputGarbledValues != null){
				setInputKeys(allInputGarbledValues);
			}
			//Set the output keys if there are.
			if (allOutputGarbledValues != null){
				setOutputKeys(allOutputGarbledValues);
			}
			//Garble the circuit using the seed.
			garble(seed);
		}
		
		//After there are garbled tables and translation table, we need to verify that they are the same as the given one.
		return verifyHashedCircuit(hash, hashedCircuit);
	}
	
	/**
	 * Checks that the given secretKey arrays contain the same keys.
	 * @param secretKeys The first array to compare.
	 * @param secretKeys2 The second array to compare.
	 * @return true if the given arrays are the same; False, otherwise.
	 */
	private boolean checkEquality(SecretKey[] secretKeys, SecretKey[] secretKeys2) {
		if (secretKeys.length != secretKeys2.length){
			return false;
		}
		
		boolean valid = true;
		for (int i=0; i<secretKeys.length; i++){
			valid = valid && equalKey(secretKeys[i], secretKeys2[i]);
		}
		return valid;
	}

	/**
	 * Verifies the output identity gates.
	 * @param allWireValues contains both keys for each wire needed by the output gates.
	 * @return true if the output identity gates are verified; False, otherwise.
	 */
  	private boolean verifyOutputs(Map<Integer, SecretKey[]> allWireValues) {
  		int outputNumber = outputIndices.length;
		
  		//Check that the number of output identity gates is the same as the number of output wires.
		if (outputIdentityGates.length != outputNumber) {
			return false;
		}
		
		//Create an identity truth table.
		BitSet truthTable = new BitSet();
		truthTable.set(1);
		int[] inputIndex = new int[1];
		int[] outputIndex = new int[1];
		int index;
		
		//Verify each identity gate. This is done by creating a Gate object with the identity truth table and the right wires indices.
		//The verify method of the identity gate check the gate is consistent with the given creaated gate.
		for (int i = 0; i < outputNumber; i++) {
  			try {
  				index = outputIndices[i];
  				inputIndex[0] = index; 			//The input wire index of gate represents wire w should be w.
  				outputIndex[0] = -1*(index+1);	//The input wire index of gate represents wire w should be -(w+1).
  				Gate identity = new Gate(i, truthTable, inputIndex, outputIndex);
				if (outputIdentityGates[i].verify(identity, allWireValues) == false) {
					return false;
				}
			} catch (InvalidKeyException e) {
				// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
			} catch (IllegalBlockSizeException e) {
				// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
			} catch (CiphertextTooLongException e) {
				// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
			}
  		}
		return true;
	}

  	/**
	 * Verifies the input identity gates.
	 * @param allWireValues contains both keys for each wire needed by the input gates.
	 * @return true if the input identity gates are verified; False, otherwise.
	 */
	protected boolean verifyInputs(ArrayList<Integer> inputIndices, Map<Integer, SecretKey[]> allWireValues) {
  		
		int inputNumber = inputIndices.size();
		
		//Check that the number of output identity gates is the same as the number of output wires.
		if (inputIdentityGates.length != inputNumber) {
			return false;
		}
   
		//Create an identity truth table.
		BitSet truthTable = new BitSet();
		truthTable.set(1);
		int[] inputIndex = new int[1];
		int[] outputIndex = new int[1];
		int index;
		
		//Verify each identity gate. This is done by creating a Gate object with the identity truth table and the right wires indices.
		//The verify method of the identity gate check the gate is consistent with the given creaated gate.
		for (int i = 0; i < inputNumber; i++) {
  			try {
  				index = inputIndices.get(i);
  				inputIndex[0] = -1*(index+1); 	//The input wire index of gate represents wire w should be -(w+1).
  				outputIndex[0] = index;			//The output wire index of gate represents wire w should be w.
  				Gate identity = new Gate(i, truthTable, inputIndex, outputIndex);
				if (inputIdentityGates[i].verify(identity, allWireValues) == false) {
					return false;
				}
			} catch (InvalidKeyException e) {
				// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
			} catch (IllegalBlockSizeException e) {
				// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
			} catch (CiphertextTooLongException e) {
				// Should not occur since the keys were generated through the encryption scheme that generates keys that match it.
			}
  		}
		return true;
	}
	
	@Override
	public byte[] getHashedCircuit(CryptographicHash hash){
		//Get the garbled tables arrays
		byte[][] tables = garbledTablesHolder.toDoubleByteArray();
		
		//Update the hash with each gate's garbled table.
		for (int i=0; i<tables.length; i++){
			if (tables[i] != null){
				hash.update(tables[i], 0, tables[i].length);
			}
		}
		
		Byte signalbit;
		byte[] signalBitArray;
		//Update the hash with each signal bit.
		for (Object index : gbc.getOutputWireIndices()){
			signalbit = gbc.getTranslationTable().get(index);
			signalBitArray = new byte[1];
			signalBitArray[0] = signalbit;
			hash.update(signalBitArray, 0, 1);
			
		}
		
		//Compute the hash function.
		byte[] output = new byte[hash.getHashedMsgSize()];
		hash.hashFinal(output, 0);
		
		return output;
	}
	
	@Override
	public boolean verifyHashedCircuit(CryptographicHash hash, byte[] hashedCircuit){
		//Get the result of the hash function on the exist garbled tables and translation table.
		byte[] hashedTables = getHashedCircuit(hash);
		
		//Verify the lengths of both hash results.
		int size = hashedCircuit.length;
		if (size != hashedTables.length){
			return false;
		}
		
		//Verify the content of both hash results.
		for (int i=0; i<size; i++){
			if (hashedCircuit[i] != hashedTables[i]){
				return false;
			}
		}
		
		return true;
	}

	@Override
  	public Map<Integer, Wire> translate(Map<Integer, GarbledWire> garbledOutput){
		//The translation is done using the translation table that uses the signal bit approach.
		//In case of extended circuit, there is a situation where the last keys were given by the user and thus they are not 
		//necessarily complied to the signal bit approach.
		//For that reason, we save the output of the inner circuit and use it in order to translate.
		//The output will be the same because the added output gates are the identity gates.
  		return gbc.translate(outputFromInnerCircuit);

	}
	
	@Override
	public List<Integer> getInputWireIndices(int partyNumber) throws NoSuchPartyException {
		
		return gbc.getInputWireIndices(partyNumber);
	}

	@Override
	public int getNumberOfInputs(int partyNumber) throws NoSuchPartyException {
		
		return gbc.getNumberOfInputs(partyNumber);
	}
  
	@Override
	public GarbledTablesHolder getGarbledTables(){
		return garbledTablesHolder;
	}
  
	@Override
	public void setGarbledTables(GarbledTablesHolder garbledTables){
		if (!(garbledTables instanceof ExtendedGarbledTablesHolder)){
			throw new IllegalArgumentException("garbledTables should be an instance of ExtendedGarbledTablesHolder");
		}
		
		ExtendedGarbledTablesHolder holder = (ExtendedGarbledTablesHolder) garbledTables;
		
		this.garbledTablesHolder.setGarbledTables(holder.getInternalGarbledTables(), holder.getInputGarbledTables(), holder.getOutputGarbledTables());
		generateInputOutputGates();
		gbc.setGarbledTables(holder.getInternalGarbledTables());
	}
	
	/**
	 * In case the user set input and/or output keys, create the corresponding gates.<P>
	 * The algorithm to add the gates:<P>
	 *	1. For each input wire i, add a gate with input wire -(i+1) and the output wire i. <P>
	 *	2. For each output wire i, add a gate with input wire i and the output wire -(i+1). <P>
	 *	
	 * @param values The values returned from the inner circuit's garble function.
	 * @return The input and output keys of this circuit, along with the translation table of the inner circuit. 
	 */
	private void generateInputOutputGates() {
		
		//In case the user set the input keys, create the input identity gates.
		if (garbledTablesHolder.getInputGarbledTables().toDoubleByteArray() != null){
			
			int size = inputIndices.size();
			createInputIdentityGates(size);
		}
		
		//In case the user set the output keys, create the output identity gates.
		if (garbledTablesHolder.getOutputGarbledTables().toDoubleByteArray() != null){
			
			int size = outputIndices.length;
			createOutputIdentityGates(size);
		}
	}

	private void createOutputIdentityGates(int size) {
		//Create an identity gates array in the right size.
		outputIdentityGates = new IdentityGate[size];
		int index;
		//Create each output identity gate with input wire i and the output wire -(i+1). 
		for (int i=0; i<size; i++){
			index = outputIndices[i];
			if (prg == null){	
				outputIdentityGates[i] = new IdentityGate(i, index, -1*(index+1), mes, garbledTablesHolder.getOutputGarbledTables());
			} else{
				outputIdentityGates[i] = new IdentityGate(i, index, -1*(index+1), mes, garbledTablesHolder.getOutputGarbledTables(), prg);
			}
		}
	}

	private void createInputIdentityGates(int size) {
		//Create an identity gates array in the right size.
		inputIdentityGates = new IdentityGate[size];
		int index;
		//Create each input identity gate with input wire -(i+1) and the output wire i. 
		for (int i=0; i<size; i++){
			index = inputIndices.get(i);
			if (prg == null){	
				inputIdentityGates[i] = new IdentityGate(i, -1*(index+1), index, mes, garbledTablesHolder.getInputGarbledTables());
			} else {
				inputIdentityGates[i] = new IdentityGate(i, -1*(index+1), index, mes, garbledTablesHolder.getInputGarbledTables(), prg);
			}
		}
	}

	@Override
	public int[] getOutputWireIndices() {
		return gbc.getOutputWireIndices();
	}

	@Override
	public int getNumberOfParties() {
		
		return gbc.getNumberOfParties();
	}

	@Override
	public Map<Integer, Wire> verifiedTranslate(Map<Integer, GarbledWire> garbledOutput, Map<Integer, SecretKey[]> allOutputWireValues)
			throws CheatAttemptException {
		
		//For each wire check that the given output is one of two given possibilities.
		for (int index : getOutputWireIndices()){
			SecretKey[] keys = allOutputWireValues.get(index);
			SecretKey output = garbledOutput.get(index).getValueAndSignalBit();
			
			if (!(equalKey(output, keys[0])) && !(equalKey(output, keys[1]))){
				throw new CheatAttemptException("The given output value is not one of the two given possible values");
			}
		}
		
		//After verified, the output can be translated.
		return translate(garbledOutput);
		
	}
	
	/**
	 * Check that the given keys are the same.
	 * @param output The first key to compare.
	 * @param key The second key to compare.
	 * @return true if both keys are the same; False otherwise.
	 */
	private boolean equalKey(SecretKey output, SecretKey key){
		byte[] outputBytes = output.getEncoded();
		byte[] keyBytes = key.getEncoded();
		
		//Compare the keys' lengths.
		if (outputBytes.length != keyBytes.length){
			return false;
		}
		
		int length = outputBytes.length;
		
		//compare the keys' contents.
		for (int i=0; i<length; i++){
			if (outputBytes[i] != keyBytes[i]){
				return false;
			}
		}
		return true;
	}

	@Override
	public HashMap<Integer, Byte> getTranslationTable() {
		
		return gbc.getTranslationTable();
	}

	@Override
	public void setTranslationTable(HashMap<Integer, Byte> translationTable) {
		gbc.setTranslationTable(translationTable);
		
	}

}
