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
import java.util.HashMap;
import java.util.Map;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.Wire;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.exceptions.CannotBeGarbledExcpetion;
import edu.biu.scapi.exceptions.CiphertextTooLongException;
import edu.biu.scapi.exceptions.KeyNotSetException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.PlaintextTooLongException;
import edu.biu.scapi.exceptions.TweakNotSetException;

/**
 * This inherits from {@code FreeXORGarbledBooleanCircuit} and has its functionality and optimizations. As a circuit, it contains
 * all functionality that has to do with translation and the translation table.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class FreeXORGarbledBooleanCircuit extends
		FreeXORGarbledBooleanSubCircuit implements GarbledBooleanCircuit {

	private static final long serialVersionUID = 3250047190442775316L;
	
	/**
	   * The translation table stores the signal bit for the output wires. Thus, it
	   * just tells you whether the wire coming out is a 0 or 1 but nothing about
	   * the plaintext of the wires is revealed. This is good since it is possible
	   * that a circuit output wire is also an input wire to a different gate, and
	   * thus if the translation table contained the plaintext of both possible
	   * values of the output Wire, the constructing party could change the value of
	   * the wire when it is input into a gate, and privacy and/or correctness will
	   * not be preserved. Therefore, we only reveal the signal bit, and the other
	   * possible value for the wire is not stored on the translation table.
	   */
	  private Map<Integer, Integer> translationTable;
	  

	/**
	 * Calls the super class construction to fill all data but the translations table. The translation table which does not exist in
	 * the super class sub circuit is filled in this constructor
	 * 
	 * @param ungarbledCircuit the base boolean circuit
	 * @param mes multi encryption scheme
	 * @param allInputWireValues a map to hold the 0 and 1 keys of the input. Can either be empty and be fill by the super class, or 
	 * 						     can already hold the keys in which case the super class uses these values for the encryptions.
	 * 
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws KeyNotSetException
	 * @throws TweakNotSetException
	 * @throws PlaintextTooLongException
	 * @throws NoSuchPartyException
	 * @throws CannotBeGarbledExcpetion
	 */
	public FreeXORGarbledBooleanCircuit(BooleanCircuit ungarbledCircuit,
			MultiKeyEncryptionScheme mes, 
			Map<Integer, SecretKey[]> allInputWireValues)
					throws InvalidKeyException, IllegalBlockSizeException,
					KeyNotSetException, TweakNotSetException, PlaintextTooLongException, NoSuchPartyException, CannotBeGarbledExcpetion {

		
		//set the signal bits to pass on to the sub circuit creator. This is not saved in the class for security reasons
		translationTable = new HashMap<Integer, Integer>();
				
		Map<Integer, Integer> signalBits = new HashMap<Integer, Integer>();//the signal bits for every wire in the circuit
		Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
		
		//create the sub circuit
		subCircuitCreator(ungarbledCircuit, mes, allInputWireValues, allWireValues, signalBits);
		
		
		//fill the translation table 
		for (int n : outputWireLabels) {
			translationTable.put(n, signalBits.get(n));
			
		}		
		
	}

	
	/**
	 * Calls the super class construction to fill all data but the translations table. The translation table which does not exist in
	 * the super class sub circuit is filled in this constructor
	 * 
	 * @param ungarbledCircuit the base boolean circuit
	 * @param mes multi encryption scheme
	 * @param allInputWireValues a map to hold the 0 and 1 keys of the input. Can either be empty and be fill by the super class, or 
	 * 						     can already hold the keys in which case the super class uses these values for the encryptions.
	 * 
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws KeyNotSetException
	 * @throws TweakNotSetException
	 * @throws PlaintextTooLongException
	 * @throws NoSuchPartyException
	 * @throws CannotBeGarbledExcpetion
	 */
	public FreeXORGarbledBooleanCircuit(BooleanCircuit ungarbledCircuit,
			MultiKeyEncryptionScheme mes, 
			Map<Integer, SecretKey[]> allInputWireValues, Map<Integer, SecretKey[]> allOutputWireValues)
					throws InvalidKeyException, IllegalBlockSizeException,
					KeyNotSetException, TweakNotSetException, PlaintextTooLongException, NoSuchPartyException, CannotBeGarbledExcpetion {

		
		//set the signal bits to pass on to the sub circuit creator. This is not saved in the class for security reasons
		translationTable = new HashMap<Integer, Integer>();
				
		Map<Integer, Integer> signalBits = new HashMap<Integer, Integer>();//the signal bits for every wire in the circuit
		Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
		
		//create the sub circuit
		subCircuitCreator(ungarbledCircuit, mes, allInputWireValues,  allWireValues, signalBits);
		
		
		//fill the translation table 
		for (int n : outputWireLabels) {
			translationTable.put(n, signalBits.get(n));
			
			//add both values of output wire labels to the allOutputWireLabels Map that
			//was passed as a parameter
			allOutputWireValues.put(n, allWireValues.get(n));
			
		}		
		
	}
	
	

	/**
	 * Does the translation from the resulting garbled wires to wires. This is done through the utility class.
	 */
	public Map<Integer, Wire> translate(Map<Integer, GarbledWire> garbledOutput) {

		CircuitUtil util = new CircuitUtil();
		
		//call the utility class to do the translation
		return util.translate(garbledOutput, translationTable, outputWireLabels);
		
		
	}
	
	/**
	 * Does the verification that has to do with the translation table after calling the super class verification.
	 * 
	 * @param ungarbledCircuit the boolean circuit
	 * @param allInputWireValues both wire keys of the input wires keys 
	 * @param allWireValues keys of all wires
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws CiphertextTooLongException
	 * @throws KeyNotSetException
	 * @throws TweakNotSetException
	 */
	 public boolean verify(BooleanCircuit ungarbledCircuit,
	      Map<Integer, SecretKey[]> allInputWireValues,
	      Map<Integer, SecretKey[]> allWireValues) throws InvalidKeyException,
	      IllegalBlockSizeException, CiphertextTooLongException,
	      KeyNotSetException, TweakNotSetException {
		  
		 //first call the super class verify to verify the sub circuit data.
	    if( verifySubCircuit(ungarbledCircuit, allInputWireValues, allWireValues)==true){
	    	
	    	CircuitUtil util = new CircuitUtil();
	    	
	    	//call the utility class to check validity related to the translation table.
	    	return util.verifyCircuitTranslation(translationTable, outputWireLabels, allWireValues); 
	    }
	    
	    return false;
	    
	    
	 }
	 
    /**
    * Returns the translation table of the circuit. This is necessary since the conrtructor of the circuit may want to pass the
    * translation table to other party. Usually, this will be used when the other party (not the constructor of the circuit) 
    * sets the garbled tables and needs the translation table as well to complete the construction of the circuit
    * 
    * @return The translation table of the circuit.  
    *           
    */
	@Override
	public Map<Integer, Integer> getTranslationTable() {
		
		return translationTable;
	}


	/**
	 * Sets the translation table of the circuit. This is necessary when the garbled tables where set and we would like to 
	 * compute the circuit later on. 
	 * @param translationTable
	 */
	@Override
	public void setTranslationTable(Map<Integer, Integer> translationTable) {
		
		this.translationTable = translationTable;
		
	}
	
}
