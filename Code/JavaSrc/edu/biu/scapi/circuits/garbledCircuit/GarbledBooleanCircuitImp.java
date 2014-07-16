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
import edu.biu.scapi.circuits.encryption.AESFixedKeyMultiKeyEncryption;
import edu.biu.scapi.exceptions.CiphertextTooLongException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;
import edu.biu.scapi.primitives.prg.PseudorandomGenerator;

/**
 * A concrete implementation of GarbledBooleanCircuit that is common for all types of circuits.<p>
 * It gets an input a object in the constructor that defines which specific type of circuit it really is.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class GarbledBooleanCircuitImp extends GarbledBooleanCircuitAbs implements GarbledBooleanCircuit {

	private BooleanCircuit bc;			// The Boolean circuit that this circuit should be the garbling of.
	private CircuitTypeUtil util; 		//Executes all functionalities that specific to the circuit type.
	private PseudorandomGenerator prg;  //used in case of generating the keys using a seed.
	private GarbledGate[] gates; 		// The garbled gates of this garbled circuit.
	
  	/**
	 * Default constructor. Sets the given boolean circuit and creates a Free XOR circuit using a AESFixedKeyMultiKeyEncryption.
	 * 
	 */
	public GarbledBooleanCircuitImp(BooleanCircuit bc){
		this(new FreeXORGarblingParameters(bc, new AESFixedKeyMultiKeyEncryption(), false));
		
	}
	
	/**
	 * A constructor that gets an input object and creates the circuit with its contents.<p>
	 * This constructor should be used in case the garbling is done using the encryption scheme. 
	 * In case the user want to garble using a seed, use the constructor that gets a prg.<p>
	 * The created circuit will be "empty", without garbled tables. <p>
	 * After this constructor the circuit is not complete, one of the garble functions should be called in order to 
	 * fill the garbled tables and translation table.
	 * @param input Specifies which concrete type of circuit to implement.
	 */
	public GarbledBooleanCircuitImp(GarblingParameters input){
		//Create an empty garbled tables.
		garbledTablesHolder = new BasicGarbledTablesHolder(new byte[input.getUngarbledCircuit().getGates().length][]);
		//Call the function that creates the gates.
		doConstruct(input);
	}
	
	/**
	 * A constructor that gets a prg and an input object and creates the circuit with their contents.<p>
	 * This constructor should be used in case the garbling is done using a seed. 
	 * In case the user want to garble using an encryption scheme, use the constructor that does not get a prg.<p>
	 * The created circuit will be "empty", without garbled tables. <p>
	 * After this constructor the circuit is not complete, one of the garble functions should be called in order to 
	 * create the underlying gates.
	 * @param input Specifies which concrete type of circuit to implement.
	 */
	public GarbledBooleanCircuitImp(GarblingParameters input, PseudorandomGenerator prg){
		//Create an empty garbled tables.
		garbledTablesHolder = new BasicGarbledTablesHolder(new byte[input.getUngarbledCircuit().getGates().length][]);
		this.prg = prg;
		
		//Call the function that creates the gates.
		doConstruct(input);
	}
	
	/**
	 * Constructs a circuit from the given input.
	 * @param input Specifies which concrete type of circuit to implement.
	 */
	private void doConstruct(GarblingParameters input) {
		// The input object defines which concrete circuit to use. Thus, it can create the utility class that matches this type of circuit.
		util = input.createCircuitUtil();
		
		//Extracts parameters from the given boolean circuit.
		bc = input.getUngarbledCircuit();
		outputWireIndices = bc.getOutputWireIndices();
		numberOfParties = bc.getNumberOfParties();
		
		//Gets the input indices for each party.
		for (int i=1; i<=numberOfParties; i++){
			ArrayList<Integer> partyInputIndices = null;
			try {
				partyInputIndices = bc.getInputWireIndices(i);
			} catch (NoSuchPartyException e) {
				// Should not occur since the called party numbers are correct.
			}
			eachPartysInputWires.add(partyInputIndices);
			
		}
		
		//Create the circuit's gates.
		gates = util.createGates(bc.getGates(), garbledTablesHolder);
	}
	
	@Override
  	public CircuitCreationValues garble() {
		//Call the utility class to generate the keys and create the garbled tables.
		CircuitCreationValues values = util.garble(bc, garbledTablesHolder, gates);
		translationTable = values.getTranslationTable();
		return values;
	}
	
	@Override
	public CircuitCreationValues garble(byte[] seed) throws InvalidKeyException {
		if (prg == null){
			throw new IllegalStateException("This circuit can not use seed to generate keys since it has no prg. Use the other garble() function");
		}
		//Call the utility class to generate the keys and create the garbled tables.
		CircuitCreationValues values = util.garble(bc, garbledTablesHolder, gates, prg, seed);
		translationTable = values.getTranslationTable();
		return values;
	}
 
  	@Override
  	public HashMap<Integer, GarbledWire> compute() throws NotAllInputsSetException{
  		//Check that all the inputs have been set.
  		for (int i=1; i <= getNumberOfParties(); i++){
  			List<Integer> wireNumbers = null;
			try {
				wireNumbers = getInputWireIndices(i);
			} catch (NoSuchPartyException e) {
				// Should not occur since the parties numbers are between 1 to getNumberOfParties.
			}
  			
	  		for (int wireNumber : wireNumbers){
	  			if (!computedWires.containsKey(wireNumber)) {
	  				throw new NotAllInputsSetException();
	  			}
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
  		 * Copy only the values that we need to retain -- i.e. the values of the output wires to a new map to be returned. 
  		 * The computedWire's map contains more values than we need to retain as it has values for all wires, 
  		 * not only circuit output wires.
  		 */
  		HashMap<Integer, GarbledWire> garbledOutput = new HashMap<Integer, GarbledWire>();
  		for (int w : outputWireIndices) {
  			garbledOutput.put(w, computedWires.get(w));
  		}

  		return garbledOutput;
  	}	
  	
  	byte getKeySignalBit(SecretKey key){
  		return (byte) ((key.getEncoded()[key.getEncoded().length - 1] & 1) == 0 ? 0 : 1);
  	}
  	
  	@Override
  	public boolean internalVerify(Map<Integer, SecretKey[]> allInputWireValues, Map<Integer, SecretKey[]> allOutputWireValues){
  	
  		/*
  		 * We will add values of non-input wires to the map as we compute them (this will take place in the Gate's 
  		 * verify method that we are about to call). In order to not change the input Map, we first copy its contents to a new Map.
  		 */
  		Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();  
		allWireValues.putAll(allInputWireValues); 
		
		
  		// First we check that the number of gates is the same.
  		if (gates.length != bc.getGates().length) {
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
				if (gates[i].verify(bc.getGates()[i], allWireValues) == false) {
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
  		
		//Put the output keys in the given output array.
  		for (int w : outputWireIndices) {
  			allOutputWireValues.put(w, allWireValues.get(w));
  		}
  		return true;
  	}
  
	@Override
	public void setGarbledTables(GarbledTablesHolder garbledTables){
		if (!(garbledTables instanceof BasicGarbledTablesHolder)){
			throw new IllegalArgumentException("garbledTables should be an instance of BasicGarbledTablesHolder");
		}
		((BasicGarbledTablesHolder)garbledTablesHolder).setGarbledTables(garbledTables.toDoubleByteArray());
	}
}
