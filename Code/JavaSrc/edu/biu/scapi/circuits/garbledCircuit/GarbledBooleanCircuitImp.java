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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.Wire;
import edu.biu.scapi.exceptions.CiphertextTooLongException;
import edu.biu.scapi.exceptions.InvalidInputException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;

/**
 * Concrete implementation of GarbledBooleanCircuit that common for all types of circuits.<p>
 * It gets an input object in the constructor that defines which specific type of circuit it really is.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class GarbledBooleanCircuitImp implements GarbledBooleanCircuit {

	protected CircuitTypeUtil util; 	//Executes all functionalities that specific to the circuit type.
	private int[] outputWireLabels;
	private boolean[] isInputSet; 		//For each party we save a boolean indicates if the input for that party has been set.
	private ArrayList<ArrayList<Integer>> eachPartysInputWires; //Input wires' labels of each party.
  	protected GarbledGate[] gates; // The garbled gates of this garbled circuit.
  	private int numberOfParties;
	
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
  	protected GarbledTablesHolder garbledTablesHolder;
  	
  	//A map that is used during computation to map a {@code GarbledWire}'s label to the computed and set {@code GarbledWire}.
  	private Map<Integer, GarbledWire> computedWires = new HashMap<Integer,GarbledWire>();

  	/*
	 * The translation table stores the signal bit for the output wires. Thus, it just tells you whether the wire coming out is a 
	 * 0 or 1 but nothing about the plaintext of the wires is revealed. This is good since it is possible that a circuit output 
	 * wire is also an input wire to a different gate, and thus if the translation table contained the plaintext of both possible
	 * values of the output Wire, the constructing party could change the value of the wire when it is input into a gate, and 
	 * privacy and/or correctness will not be preserved. Therefore, we only reveal the signal bit, and the other
	 * possible value for the wire is not stored on the translation table.
	 */
	protected HashMap<Integer, Byte> translationTable;
	
	/**
	 * Constructor that gets an input object and create the circuit with it contents.<p>
	 * The created circuit will be "empty", without garbled tables. <p>
	 * After this constructor the circuit is not complete, one of the generateKeysAndSetTables functions should be called in order to 
	 * create the underlying gates.
	 * @param input specifies which concrete type of circuit to implement.
	 */
	public GarbledBooleanCircuitImp(CircuitInput input){
		//Create an empty garbled tables.
		garbledTablesHolder = new GarbledTablesHolder(new byte[input.getUngarbledCircuit().getGates().length][]);
		
		doConstruct(input);
	}
	
	/**
	 * Constructor that gets an input object, garbled tables and translation tables and create the circuit with them.<p>
	 * After this constructor the circuit is complete and ready to be used.
	 * @param input input specifies which concrete type of circuit to implement.
	 * @param garbledTables 
	 * @param translationTable
	 */
	public GarbledBooleanCircuitImp(CircuitInput input, byte[][] garbledTables, HashMap<Integer, Byte> translationTable){
		//Sets the given garbled tables.
		this.garbledTablesHolder = new GarbledTablesHolder(garbledTables);
		this.translationTable = translationTable;
		
		doConstruct(input);
	}
	
	/**
	 * Constructs a circuit from the given input.
	 * @param input input specifies which concrete type of circuit to implement.
	 */
	private void doConstruct(CircuitInput input) {
		// The input object defines which concrete circuit to use. Thus, it can create the utility class that matches this type of circuit.
		util = input.createCircuitUtil();
		
		//Extracts parameters from the given boolean circuit.
		BooleanCircuit ungarbledCircuit = input.getUngarbledCircuit();
		outputWireLabels = ungarbledCircuit.getOutputWireLabels();
		numberOfParties = ungarbledCircuit.getNumberOfParties();
		isInputSet = new boolean[numberOfParties];
		eachPartysInputWires = new ArrayList<ArrayList<Integer>>();
		
		//Gets the input labels for each party.
		for (int i=1; i<=numberOfParties; i++){
			ArrayList<Integer> partyInputLabels = null;
			try {
				partyInputLabels = ungarbledCircuit.getInputWireLabels(i);
			} catch (NoSuchPartyException e) {
				// Should not occur since the called party numbers are correct.
			}
			eachPartysInputWires.add(partyInputLabels);
			if(partyInputLabels.size()==0){
				isInputSet[i-1] = true;
			}
			
		}
		
		//Create the circuit's gates.
		gates = util.createGates(ungarbledCircuit.getGates(), garbledTablesHolder);
	}
	
	@Override
  	public CircuitCreationValues garble(BooleanCircuit ungarbledCircuit) {
		//Call the utility class to generate the keys and create the garbled tables.
		CircuitCreationValues values = util.garble(ungarbledCircuit, garbledTablesHolder, gates);
		translationTable = values.getTranslationTable();
		return values;
	}
	
	@Override
	public CircuitCreationValues garble(BooleanCircuit ungarbledCircuit, Map<Integer, SecretKey[]> partialWireValues) {
		//Call the utility class to generate the keys and create the garbled tables.
		CircuitCreationValues values = util.garble(ungarbledCircuit, garbledTablesHolder, gates, partialWireValues);
		translationTable = values.getTranslationTable();
		return values;
	}
	
  	@Override
 	public void setGarbledInputFromUngarbledInput(Map<Integer, Byte> ungarbledInput, Map<Integer, SecretKey[]> allInputWireValues, int partyNumber) throws NoSuchPartyException {
  		
  		Map<Integer, GarbledWire> inputs = new HashMap<Integer, GarbledWire>();
  		
  		//Get he labels of the given party.
  		List<Integer> labels = getInputWireLabels(partyNumber);
  		int numberOfInputs = labels.size();
  		
  		//For each label, fill the map with wire label and garbled input.
  		for (int i = 0; i < numberOfInputs; i++) {
  			int label = labels.get(i);
  			inputs.put(label, new GarbledWire(allInputWireValues.get(label)[ungarbledInput.get(label)]));
  		}
  		setInputs(inputs, partyNumber);
  	}
  
  	@Override
  	public void setInputs(Map<Integer, GarbledWire> presetInputWires, int partyNumber) throws NoSuchPartyException {
  		
  		if (partyNumber>numberOfParties){
  			throw new NoSuchPartyException();
  		}
  		
  		computedWires.putAll(presetInputWires);
  	    isInputSet[partyNumber-1] = true;
 	}
 
  	@Override
  	public Map<Integer, GarbledWire> compute() throws NotAllInputsSetException{
  		int numberOfParties = isInputSet.length;
  		//check that all the input has been set.
  		for (int i=0; i<numberOfParties; i++){
  			if (isInputSet[i] == false) {
  				throw new NotAllInputsSetException();
  			}
  		}
  		/*
  		 * We use the interface GarbledGate and thus this works for all implementing classes. The compute method of the 
  		 * specific garbled gate being used will be called. This allows us to have circuits with different types of gates 
  		 * {i.e a FreeXORGarbledBooleanCircuit contains both StandardGarbledGates and FreeXORGates) and this will work for all the gates.
  		 */
  		for (GarbledGate g : gates) {
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
  		
  		/*
  		 * Copy only the values that we need to retain--i.e. the values of the output wires to a new map to be returned. 
  		 * The computedWire's map contains more values than we need to retain as it has values for all wires, 
  		 * not only circuit output wires.
  		 */
  		Map<Integer, GarbledWire> garbledOutput = new HashMap<Integer, GarbledWire>();
  		for (int w : outputWireLabels) {
  			garbledOutput.put(w, computedWires.get(w));
  		}

  		return garbledOutput;
  	}	

  	@Override
  	public boolean verify(BooleanCircuit ungarbledCircuit, Map<Integer, SecretKey[]> allInputWireValues) throws InvalidInputException{
	  
  		Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();  
		/*
	     * We are going to need to add values for non-input wires to the map as we compute them(this will take place in the Gate's 
	     * verify method that we are about to call). In order to not change the input Map, we first copy its contents to a new Map.
	     */
		allWireValues.putAll(allInputWireValues); 
		
		// First we check that the number of gates is the same.
  		if (gates.length != ungarbledCircuit.getGates().length) {
  			return false;
  		}
    
  		/*
  		 * Next we check gate by gate that the garbled Gate's truth table is consistent with the ungarbled gate's truth table. 
  		 * We say consistent since the gate's verify method checks the following: everywhere that the ungarbled gate's truth table 
  		 * has a 0, there is one encoding, and wherever it has a 1 there is a second encoding. Yet, under this method a 0001 truth 
  		 * table would be consistent with a 1000 truth table as we have no knowledge of what the encoded values actually translate to. 
  		 * Thus, we test for consistent and we assume that the encoded value corresponding to 0 is a 0, and that the value that 
  		 * corresponds to 1 is a 1. Based on this assumption, we map the output wire to the 0-encoded value and 1-encoded value. 
  		 * Thus if our assumption is wrong, the next gate may not verify correctly. We continue this process until we reach the circuit
  		 * output wires. At this point we confirm(or reject) all assumption by checking the translation table and seeing if the wire 
  		 * we expected to encode to a 0 was actually a 0 and the 1 was a 1. Once we have done this, we have verified the circuits are 
  		 * identical and have not relied on any unproven assumptions.
  		 */
  		for (int i = 0; i < gates.length; i++) {
  			try {
				if (gates[i].verify(ungarbledCircuit.getGates()[i], allWireValues) == false) {
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
	    
  		/*
  		 * Check that the output wires translate correctly. 
	     * At this point, we have gone through the entire circuit so allWireValues now contains both possible values for every wire
	     * in the circuit. We check the output wire values and make sure that the 0-wire translates to a 0 and that the 1 wire 
	     * translates to a 1.
	     */
  		for (int w : outputWireLabels) {
  			SecretKey zeroValue = allWireValues.get(w)[0];
  			SecretKey oneValue = allWireValues.get(w)[1];

  			byte signalBit = translationTable.get(w);
  			byte permutationBitOnZeroWire = (byte) ((zeroValue.getEncoded()[zeroValue.getEncoded().length - 1] & 1) == 0 ? 0 : 1);
  			byte permutationBitOnOneWire = (byte) ((oneValue.getEncoded()[oneValue.getEncoded().length - 1] & 1) == 0 ? 0 : 1);
  			byte translatedZeroValue = (byte) (signalBit ^ permutationBitOnZeroWire);
  			byte translatedOneValue = (byte) (signalBit ^ permutationBitOnOneWire);
  			if (translatedZeroValue != 0 || translatedOneValue != 1) {
  				return false;
  			}
  		}
  		return true;
	    
  	}
	
	/**
	 * Translates from the resulting garbled wires to wires.
	 * @param garbledOutput the result of computing the circuit. 
	 * This is result is given in garbled wires and will be translation according to the translation table.
	 * @return the translated results as wires of the boolean circuit where the value of the wires are set.
	 */
  	public Map<Integer, Wire> translate(Map<Integer, GarbledWire> garbledOutput){
  		
		Map<Integer, Wire> translatedOutput = new HashMap<Integer, Wire>();
	    
	    //Go through the output wires.
	    for (int w : outputWireLabels) {
	    	byte signalBit = translationTable.get(w);
	    	byte permutationBitOnWire = garbledOutput.get(w).getSignalBit();
	      
	    	//Calculate the resulting value.
	    	byte value = (byte) (signalBit ^ permutationBitOnWire);
	    	System.out.print(value);
	    	
	    	//Hold the result as a wire.
	    	Wire translated = new Wire(value);
	    	translatedOutput.put(w, translated);
	    }
	    System.out.println();
	    return translatedOutput;

	}
	
	@Override
	public List<Integer> getInputWireLabels(int partyNumber) throws NoSuchPartyException {
		if (partyNumber>numberOfParties){
  			throw new NoSuchPartyException();
  		}
		return eachPartysInputWires.get(partyNumber-1);
	}

	@Override
	public int getNumberOfInputs(int partyNumber) throws NoSuchPartyException {
		if (partyNumber>numberOfParties){
  			throw new NoSuchPartyException();
  		}
		return eachPartysInputWires.get(partyNumber-1).size();
	}
  
	@Override
	public byte[][] getGarbledTables(){
	  
		return garbledTablesHolder.getGarbledTables();
	}
  
	@Override
	public void setGarbledTables(byte[][] garbledTables){
		garbledTablesHolder.setGarbledTables(garbledTables);
	}
	
	@Override
	public HashMap<Integer, Byte> getTranslationTable() {
		
		return translationTable;
	}

	@Override
	public void setTranslationTable(HashMap<Integer, Byte> translationTable) {
		
		this.translationTable = translationTable;
		
	}

}
