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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.Wire;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.NoSuchPartyException;

/**
 * Abstract class that holds all the common members and functionalities of circuits.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
abstract class GarbledBooleanCircuitAbs implements GarbledBooleanCircuit{

	protected int[] outputWireIndices;	
	protected ArrayList<ArrayList<Integer>> eachPartysInputWires; //Input wires' indices of each party.
	protected int numberOfParties;
	
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
	
	/*
	 * The translation table stores the signal bit for the output wires. Thus, it just tells you whether the wire coming out is a 
	 * 0 or 1 but nothing about the key of the wires it revealed. This is good since it is possible that a circuit output 
	 * wire is also an input wire to a different gate, and thus if the translation table contained the key of both possible
	 * values of the output Wire, the constructing party could change the value of the wire when it is input into a gate, and 
	 * privacy and/or correctness will not be preserved. Therefore, we only reveal the signal bit, and the other
	 * possible value for the wire is not stored on the translation table.
	 */
	protected HashMap<Integer, Byte> translationTable;
  	
	
	//A map that is used during computation to map a {@code GarbledWire}'s index to the computed and set {@code GarbledWire}.
	protected Map<Integer, GarbledWire> computedWires;
	
	public GarbledBooleanCircuitAbs(){
		computedWires = new HashMap<Integer,GarbledWire>();
		eachPartysInputWires = new ArrayList<ArrayList<Integer>>();
	}
	
	@Override
 	public void setGarbledInputFromUngarbledInput(Map<Integer, Byte> ungarbledInput, Map<Integer, SecretKey[]> allInputWireValues) {
  		
  		Map<Integer, GarbledWire> inputs = new HashMap<Integer, GarbledWire>();
  		Set<Integer> keys = ungarbledInput.keySet();
  		
  		//For each wireIndex, fill the map with wire index and garbled input.
  		for (Integer wireIndex : keys) {
  			inputs.put(wireIndex, new GarbledWire(allInputWireValues.get(wireIndex)[ungarbledInput.get(wireIndex)]));
  		}
  		setInputs(inputs);
  	}
  
  	@Override
  	public void setInputs(Map<Integer, GarbledWire> presetInputWires) {
  		
  		computedWires.putAll(presetInputWires);
 	}
  	
  	/**
  	 * Returns the signal bit of the given key.
  	 * @param key to get the signal bit of.
  	 * @return the signal bit of the given key.
  	 */
  	abstract byte getKeySignalBit(SecretKey key);
  	
  	@Override
  	public boolean verify(Map<Integer, SecretKey[]> allInputWireValues){
	  
  		Map<Integer, SecretKey[]> outputValues = new HashMap<Integer, SecretKey[]>();  
  		
  		//Call the internalVerify function that verifies the circuit without the last part of the translation table.
		boolean verified = internalVerify(allInputWireValues, outputValues);
		
		//Check that the output wires translate correctly. 
	    //outputValues contains both possible values for every output wire in the circuit. 
		//We check the output wire values and make sure that the 0-wire translates to a 0 and that the 1 wire translates to a 1.
  		for (int w : outputWireIndices) {
  			SecretKey zeroValue = outputValues.get(w)[0];
  			SecretKey oneValue = outputValues.get(w)[1];

  			byte signalBit = translationTable.get(w);
  			byte permutationBitOnZeroWire = getKeySignalBit(zeroValue);
  			byte permutationBitOnOneWire = getKeySignalBit(oneValue);
  			byte translatedZeroValue = (byte) (signalBit ^ permutationBitOnZeroWire);
  			byte translatedOneValue = (byte) (signalBit ^ permutationBitOnOneWire);
  			if (translatedZeroValue != 0 || translatedOneValue != 1) {
  				verified = false;
  			}
  		}
  		return verified;
	}
  	
  	@Override
  	public Map<Integer, Wire> translate(Map<Integer, GarbledWire> garbledOutput){
  		
		Map<Integer, Wire> translatedOutput = new HashMap<Integer, Wire>();
		byte signalBit, permutationBitOnWire, value;
		
	    //Go through the output wires and translate it using the translation table.
	    for (int w : outputWireIndices) {
	    	signalBit = translationTable.get(w);
	    	permutationBitOnWire = garbledOutput.get(w).getSignalBit();
	      
	    	//Calculate the resulting value.
	    	value = (byte) (signalBit ^ permutationBitOnWire);
	    	
	    	//Hold the result as a wire.
	    	Wire translated = new Wire(value);
	    	translatedOutput.put(w, translated);
	    }
	
	    return translatedOutput;

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
		
		//Compare the keys' contents.	
		for (int i=0; i<length; i++){
			if (outputBytes[i] != keyBytes[i]){
				return false;
			}
		}
		return true;
	}
	
	@Override
	public List<Integer> getInputWireIndices(int partyNumber) throws NoSuchPartyException {
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
	public GarbledTablesHolder getGarbledTables(){
	  
		return garbledTablesHolder;
	}
  	
	@Override
	public HashMap<Integer, Byte> getTranslationTable(){
	  
		return translationTable;
	}
  
	@Override
	public void setTranslationTable(HashMap<Integer, Byte> translationTable){
		
		this.translationTable = translationTable;
	}

	@Override
	public int[] getOutputWireIndices() {
		return outputWireIndices;
	}

	@Override
	public int getNumberOfParties() {
		return numberOfParties;
	}
}
