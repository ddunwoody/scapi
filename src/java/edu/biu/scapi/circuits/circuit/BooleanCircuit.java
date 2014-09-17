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
package edu.biu.scapi.circuits.circuit;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import edu.biu.scapi.exceptions.CircuitFileFormatException;
import edu.biu.scapi.exceptions.InvalidInputException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;

/**
 * A software representation of a boolean circuit. <p>
 * The circuit is constructed from {@code Wire}s and {@code Gate}s. Once input has been set, the compute() function performs the 
 * computation and returns the computed output {@code Wire}s. 
 * The equals function verifies that two gates are equivalent.
 * 
 * @author Steven Goldfeder
 * 
 */

public class BooleanCircuit {

	/**
	 * An array of boolean flags set to {@code true} if and only if the input has been set for the indexed party or the indexed party has no inputs.
	 */
	private boolean[] isInputSet;
	
	/**
	 * A {@code Map} that maps the number of a {@code Wire} to the previously set {@code Wire}. 
	 * Only {@code Wire}s whose value has been set will be on this map.
	 * 
	 */
	private Map<Integer, Wire> computedWires = new HashMap<Integer,Wire>();
  
	/**
	 * An array of the {@code Gate}s of this {@code BooleanCircuit} sorted topologically.
	 */
	private Gate[] gates;
  
	/**
	 * An array containing the indices of the output {@code Wire}s of this {@code BooleanCircuit}.
	 */
	private int[] outputWireIndices;
  
	/**
	 * The number of parties that are interacting (i.e. receiving input and/or output) with this circuit.
	 */
	private int numberOfParties;  
	
	/**
	 * An arrayList containing the indices of the input {@code Wire}s of this {@code BooleanCircuit} indexed by the party number.
	 */
	private ArrayList<ArrayList<Integer>> eachPartysInputWires = new ArrayList<ArrayList<Integer>>();

	/**
	 * Constructs a BooleanCircuit from a File. <p>
	 * The File first lists the number of {@code Gate}s, then the number of parties. <p>
	 * Then for each party: party number, the number of inputs for that party, and following there is a list of indices of each of these input {@code Wire}s.<p>
	 * Next it lists the number of output {@code Wire}s followed by the index of each of these {@code Wires}. <p>
	 * Then for each gate, we have the following: number of inputWires, number of OutputWires inputWireIndices OutputWireIndices and the gate's truth Table (as a 0-1 string).<P>
	 * example file: 1 2 1 1 1 2 1 2 1 3 2 1 1 2 3 0001<p>
	 *
	 * @param f The {@link File} from which the circuit is read.
	 * @throws FileNotFoundException if f is not found in the specified directory.
	 * @throws CircuitFileFormatException if there is a problem with the format of the file.
	 */
	public BooleanCircuit(File f) throws FileNotFoundException, CircuitFileFormatException {
		this(new Scanner(f));
	}

	// Integer.parseInt(s.next()) is significantly faster than s.nextInt() so we use the former.
	/**
	 * Constructs a BooleanCircuit from a Scanner. <p>
	 * The Scanner's underyling contents contains a lists the number of {@code Gate}s, then the number of parties. <p>
	 * Then for each party: party number, the number of inputs for that party, and following there is a list of indices of each of these input {@code Wire}s.<p>
	 * Next it lists the number of output {@code Wire}s followed by the index of each of these {@code Wires}. <p>
	 * Then for each gate, we have the following: number of inputWires, number of OutputWires inputWireIndices OutputWireIndices and the gate's truth Table (as a 0-1 string).<P>
	 * example file: 1 2 1 1 1 2 1 2 1 3 2 1 1 2 3 0001<p>
	 *
	 * @param s The {@link Scanner} from which the circuit is read.
	 * @throws CircuitFileFormatException if there is a problem with the format of the circuit.
	 */
	public BooleanCircuit(Scanner s) throws CircuitFileFormatException {
	    //Read the number of gates.
	    int numberOfGates = Integer.parseInt(read(s));
	    gates = new Gate[numberOfGates];
	    //Read the number of parties.
	    numberOfParties =  Integer.parseInt(read(s));
	    isInputSet = new boolean[numberOfParties];
	    //For each party, read the party's number, number of input wires and their indices.
	    for (int i = 0; i < numberOfParties; i++) {
	    	if (Integer.parseInt(read(s)) != i+1) {//add 1 since parties are indexed from 1, not 0
	    		throw new CircuitFileFormatException();
	    	}
	    	//Read the number of input wires.
	    	int numberOfInputsForCurrentParty = Integer.parseInt(read(s));
	    	if(numberOfInputsForCurrentParty < 0){
	    		throw new CircuitFileFormatException();
	    	}
	    	boolean isThisPartyInputSet = numberOfInputsForCurrentParty == 0? true : false;
	    	isInputSet[i]=isThisPartyInputSet;
	    	
	    	ArrayList<Integer> currentPartyInput = new ArrayList<Integer>();
	    	eachPartysInputWires.add(currentPartyInput);
	    	//Read the input wires indices.
	    	for (int j = 0; j < numberOfInputsForCurrentParty; j++) {
	    		currentPartyInput.add(Integer.parseInt(read(s)));
	    	}
	    }
	    
	    /*
	     * The ouputWireIndices are the outputs from this circuit. However, this circuit may actually be a single layer of a 
	     * larger layered circuit. So this output can be part of the input to another layer of the circuit.
	     */
	    int numberOfCircuitOutputs = Integer.parseInt(read(s));
	    outputWireIndices = new int[numberOfCircuitOutputs];
	    //Read the output wires indices.
	    for (int i = 0; i < numberOfCircuitOutputs; i++) {
	    	outputWireIndices[i] = Integer.parseInt(read(s));
	    }
	    
	    int numberOfGateInputs, numberOfGateOutputs;
	    //For each gate, read the number of input and output wires, their indices and the truth table.
	    for (int i = 0; i < numberOfGates; i++) {
	    	numberOfGateInputs = Integer.parseInt(read(s));
	    	numberOfGateOutputs = Integer.parseInt(read(s));
	    	int[] inputWireIndices = new int[numberOfGateInputs];
	    	int[] outputWireIndices = new int[numberOfGateOutputs];
	    	for (int j = 0; j < numberOfGateInputs; j++) {
	    		inputWireIndices[j] = Integer.parseInt(read(s));
	    	}
	    	for (int j = 0; j < numberOfGateOutputs; j++) {
	    		outputWireIndices[j] = Integer.parseInt(read(s));
	    	}
      
	    	/*
	    	 * We create a BitSet representation of the truth table from the 01 String
	    	 * that we read from the file.
	    	 */
	    	BitSet truthTable = new BitSet();
	    	String tTable = read(s);
	    	for (int j = 0; j < tTable.length(); j++) {
	    		if (tTable.charAt(j) == '1') {
	    			truthTable.set(j);
	    		}
	    	}
	    	//Construct the gate.
	    	gates[i] = new Gate(i, truthTable, inputWireIndices, outputWireIndices);
	    }
	}

	private String read(Scanner s){
		String token = s.next();
		while (token.startsWith("#")){
			s.nextLine();
			token = s.next();
		}
		return token;
	}
	
	/**
	 * Constructs a {code BooleanCircuit} from an array of gates. <p>
	 * Each gate keeps an array of the indices of its input and output wires. The constructor is provided with a list of which 
	 * {@link Wire}s are output {@link Wire}s of the {@code BooleanCircuit}.
	 * 
	 * @param gates An array of {@link Gate}s to create from which to construct the {@code BooleanCircuit}.
	 * @param outputWireIndices An array containing the indices of the wires that will be output of the {@code BooleanCircuit}.
	 * @param eachPartysInputWires An arrayList containing the indices of the input {@code Wire}s of this
	 * {@code BooleanCircuit} indexed by the party number.
	 */
	public BooleanCircuit(Gate[] gates, int[] outputWireIndices, ArrayList<ArrayList<Integer>> eachPartysInputWires) {
		this.gates = gates;
		this.outputWireIndices = outputWireIndices;
		this.eachPartysInputWires = eachPartysInputWires;
		numberOfParties = eachPartysInputWires.size();
  	}

    /**
     * Sets the specified party's input to the circuit from a map containing constructed and set {@link Wire}s. <p>
     * It updates that this party's input has been set. 
     * Once the input is set for all parties that have input, the circuit is ready to be computed.
     * 
     * @param presetInputWires The circuit's input wires whose values have been previously set.
     * @throws NoSuchPartyException if the party number is negative or bigger then the given number of parties.
     */
	public void setInputs(Map<Integer, Wire> presetInputWires,int partyNumber) throws NoSuchPartyException {
		if(partyNumber < 1 || partyNumber > numberOfParties){
			throw new NoSuchPartyException();
		}
		computedWires.putAll(presetInputWires);
		isInputSet[partyNumber-1]=true;
	}

	/**
	 * Sets the input to the circuit by reading it from a file. <p>
	 * Written in the file is a list that contains the number of input {@link Wire}s followed by rows of {@link Wire} numbers and values.
	 * 
	 * @param inputWires The {@link File} containing the representation of the circuit's input.
	 * @throws FileNotFoundException
	 * @throws InvalidInputException 
	 * @throws NoSuchPartyException 
   	*/
	public void setInputs(File inputWires, int partyNumber) throws FileNotFoundException, InvalidInputException, NoSuchPartyException {
		if(partyNumber < 1 || partyNumber > numberOfParties){
			throw new NoSuchPartyException();
		}
		Scanner s = new Scanner(inputWires);
		int numberOfInputWires = Integer.parseInt(read(s));
		if(numberOfInputWires != getNumberOfInputs(partyNumber)){
			throw new InvalidInputException();
		}
		Map<Integer, Wire> presetInputWires = new HashMap<Integer, Wire>();
		for (int i = 0; i < numberOfInputWires; i++) {
			presetInputWires.put(Integer.parseInt(read(s)), new Wire(read(s).getBytes()[0]));
		}
		setInputs(presetInputWires,partyNumber);
	}

 	/**
 	 * Computes the circuit if the input has been set.<p>
 	 * @return a {@link Map} that maps the output {@link Wire} index to the computed {@link Wire}.
 	 * @throws NotAllInputsSetException in case there is a party that has no input.
 	 */
	public Map<Integer, Wire> compute() throws NotAllInputsSetException {
		for (int i = 0; i < numberOfParties; i++) {
			if (!isInputSet[i]) {
				throw new NotAllInputsSetException();
			}
		}
		/* Computes each Gate. 
		 * Since the Gates are provided in topological order, by the time the compute function on a given Gate is called, 
		 * its input Wires will have already been assigned values
		 */
		for (Gate g : getGates()) {
			g.compute(computedWires);
		}
		
		/*
		 * The computedWires array contains all the computed wire values, even those that it is no longer necessary to retain.
		 * So, we create a new Map called outputMap which only stores the Wires that are output Wires to the circuit. 
		 * We return outputMap.
		 */
		Map<Integer, Wire> outputMap = new HashMap<Integer, Wire>();
		for (int w : outputWireIndices) {
			outputMap.put(w, computedWires.get(w));
		}
		return outputMap;
	}

	/**
	 * The verify method tests the circuits for equality returning {@code true} if they are and {@code false}if they are not. <p>
	 * In order to be considered equal, {@code Gate}s and {@code Wire}s must be indexed identically and {@code Gate}s must contain 
	 * the same truth table.
	 * 
	 * @param obj A {@code BooleanCircuit} to be tested for equality to this {@code BooleanCircuit}
  	 * @return {@code true} if the given {@code BooleanCircuit} is equivalent to this {@code Boolean Circuit}, {@code false} otherwise.
  	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof BooleanCircuit)){
			return false;
		}
		BooleanCircuit c = (BooleanCircuit) obj;
		// First tests to see that the number of Gates is the same for each circuit. If it's not, then the two are not equal.
		if (getGates().length != c.getGates().length) {
			return false;
		}
		// Calls the equals method of the Gate class to compare each corresponding Gate. 
		// If any of them return false, the circuits are not the same.
		for (int i = 0; i < getGates().length; i++) {
			if (getGates()[i].equals(c.getGates()[i]) == false) {
				return false;
			}
		}
		return true;
	}

	/**
	 * @return an array of the {@link Gate}s of this circuit.
	 */
	public Gate[] getGates() {
		return gates;
	}

	/**
	 * @return an array of the output{@link Wire} indices of this circuit.
  	 */
	public int[] getOutputWireIndices() {
		return outputWireIndices;
	}

	/**
	 * @param partyNumber The number of the party whose input wires will be returned.
	 * @return an ArrayList containing the input {@link Wire} indices of the specified party.
	 * @throws NoSuchPartyException if the given party number is less than 1 and greater than the given number of parties.
	 */
	public ArrayList<Integer> getInputWireIndices(int partyNumber) throws NoSuchPartyException {
		if(partyNumber < 1 || partyNumber > numberOfParties){
			throw new NoSuchPartyException();
		}
		//We subtract one from the party number since the parties are indexed beginning from one, but the ArrayList is indexed from 0
		return eachPartysInputWires.get(partyNumber-1);
	}
  
	/**
	 * @param partyNumber The number of the party whose number of input wires will be returned.
	 * @return the number of input wires for the specified party.
	 * @throws NoSuchPartyException if the given party number is less than 1 and greater than the given number of parties.
	 */
	public int getNumberOfInputs(int partyNumber) throws NoSuchPartyException{
		if(partyNumber < 1 || partyNumber > numberOfParties){
			throw new NoSuchPartyException();
		}
		//We subtract one from the party number since the parties are indexed beginning from one, but the ArrayList is indexed from 0
		return eachPartysInputWires.get(partyNumber-1).size();
	}

	/**
	 * Returns the number of parties of this boolean circuit.
	 */
	public int getNumberOfParties() {
		return numberOfParties;
	}
}


