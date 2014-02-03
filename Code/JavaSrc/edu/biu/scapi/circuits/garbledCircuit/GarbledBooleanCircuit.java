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

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.Wire;
import edu.biu.scapi.exceptions.InvalidInputException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;

/**
 * {@code GarbledBooleanCircuit} is a general interface implemented by all garbled circuits--optimized or not. <p>
 * All garbled circuits have four main operations: <p>
 * 1. The construct operation which is provided by the constructors of the implementing classes following by generateWireKeysAndSetTables function. <p>
 * 2. The {@link #compute()} function computes a result on a garbled circuit that's input has been set. <p>
 * 3. The {@link #verify(BooleanCircuit, Map)} method is used in the case of a malicious adversary to verify that the garbled circuit 
 * created is an honest garbling of the agreed upon non garbled circuit. The constructing party constructs many garbled circuits and
 * the second party chooses all but one of them to verify and test the honesty of the constructing party.<p>
 * 4. The {@link #translate(Map)} that translates the garbled output from {@link #compute()} into meaningful output.<p>
 * 
 * @author Steven Goldfeder
 * 
 */
public interface GarbledBooleanCircuit {
	
	/**
	 * This method generates both keys for each input wire. Then, creates the garbled table according to that values.<p>
	 * @param ungarbledCircuit the circuit that this {@code GarbledBooleanCircuit} is supposed to be a garbling of. 
	 * @return CircuitCreationValues contains both keys for each input and output wire and the translation table.
	 */
	public CircuitCreationValues generateWireKeysAndSetTables(BooleanCircuit ungarbledCircuit) ;
	
	/**
	 * This method gets part of the keys and generates the missing keys for each wire. <p>
	 * Then, creates the garbled table according to that values.<p>
	 * This method can receive the garbled values of the input wires or the garbled values of the output wires.<p>
	 * In addition, it gets the signal bits corresponding to the partial wire's keys. <p>
	 * In case the given keys are the keys of the output wires than the given signal bits are actually the translation table.
	 * @param ungarbledCircuit the circuit that this {@code GarbledBooleanCircuit} is supposed to be a garbling of.
	 * @param partialWireValues can contain the keys of the input wires of the keys of the output wires.
	 * @param signalBits the signal bits corresponding to the given wire's keys.
	 * @return CircuitCreationValues contains both keys for each input and output wire and the translation table.
	 */
	public CircuitCreationValues generateWireKeysAndSetTables(BooleanCircuit ungarbledCircuit, Map<Integer, SecretKey[]> partialWireValues,
			HashMap<Integer, Byte> signalBits);
	
	/**
	 * This method sets the input of the circuit. <p>
	 * It takes as a parameter a {@code Map} that maps the input Wire labels to a garbled wire containing the appropriate garbled values. <p>
	 * See {@link #setGarbledInputFromUngarbledInput(File, Map)} for an alternate way of setting the input.
	 * @param presetInputWires a {@code Map} containing the input wires that have been preset with their values
	 * @param partyNumber the number of the party which we inputs belong to.
	 * @throws NoSuchPartyException 
  	 */
	public void setInputs(Map<Integer, GarbledWire> presetInputWires, int partyNumber) throws NoSuchPartyException;

	/**
	 * This method takes a map containing the {@code GarbledWire} label and <b> non garbled</b> value. <p>
	 * This method than performs the lookup on the accompanying allInputWireValues {@code Map} and sets the inputs 
	 * to the corresponding garbled outputs.
	 * @param ungarbledInput a map containing the {@code GarbledWire} label and <b> non garbled</b> value for that label. 
	 * @param allInputWireValues the map containing both garbled values for each input wire.
	 * @param partyNumber the number of the party which we inputs belong to.
	 * @throws NoSuchPartyException 
	 */
	public void setGarbledInputFromUngarbledInput(Map<Integer, Byte> ungarbledInput, Map<Integer, SecretKey[]> allInputWireValues, int partyNumber) throws NoSuchPartyException;
 
	/**
	 * This method computes the circuit if input has been set. <p>
	 * It returns a {@code Map} containing the garbled output. This output can be translated via the {@link #translate(Map)} method.
	 * @return returns a {@code Map} that maps the label of the output wire to the garbled value of the wire
	 * @throws NotAllInputsSetException if not all the input has been set.
	 *        
	 */
	public Map<Integer, GarbledWire> compute() throws NotAllInputsSetException;

	/**
     * The verify method is used in the case of malicious adversaries.<p>
     * Alice constructs n circuits and Bob can verify n-1 of them(of his choosing) to confirm that they are indeed garbling of the 
     * agreed upon non garbled circuit. In order to verify, Alice has to give Bob both keys for each of the input wires.
     * @param ungarbledCircuit the circuit that this {@code GarbledBooleanCircuit} is supposed to be a garbling of. 
     * This is the circuit that Alice and Bob agreed upon in Yao's protocol. We are verifying that this {@code GarbledBooleanCircuit} 
     * is indeed a garbling of the agreed upon ungarbled circuit.
     * @param allInputWireValues a {@Map} containing both keys for each input wire.
     * For each input wire label, the map contains an array of two values. The value in the 0 position is the 0 encoding, and the
     * value in the 1 position is the 1 encoding.
     * @return {@code true} if this {@code GarbledBooleanCircuit} is a garbling of the ungarbledCircuit, {@code false} if it is not
     * @throws InvalidInputException in case there is a problem with the given keys.
     */
	public boolean verify(BooleanCircuit ungarbledCircuit, Map<Integer, SecretKey[]> allInputWireValues) throws InvalidInputException;

	/**
	 * Translates the garbled output obtained from the {@link #compute()} function into meaningful(i.e. 0-1) output.<p>
	 * @param garbledOutput a {@code Map) that containing the garbled output. This map maps the output wire labels to {@code GarbledWire}s
	 * @return a {@code Map} that maps the output wire labels to ungarbled {@code Wire}s that are set to either 0 or 1.
	 */
	public Map<Integer, Wire> translate(Map<Integer, GarbledWire> garbledOutput);

	/**
	 * The garbled tables are stored in the circuit for all the gates. This method returns the garbled tables. <p>
	 * This function is useful if we would like to pass many garbled circuits built on the same boolean circuit. <p>
	 * This is a compact way to define a circuit, that is, two garbled circuit with the same multi encryption scheme and the same
	 * basic boolean circuit only differ in the garbled tables and translation table. <p>
	 * Thus we can hold one garbled circuit for all the circuits and only replace the garbled tables (and translation tables if 
	 * necessary). The advantage is that the size of the tables only is much smaller that all the information stored in the circuit 
	 * (gates and other member variables). The size becomes important when sending large circuits.
	 * 
	 */
	public byte[][] getGarbledTables();
	
	
	/**
	 * Sets the garbled tables of this circuit.<p>
	 * This function is useful if we would like to pass many garbled circuits built on the same boolean circuit. <p>
	 * This is a compact way to define a circuit, that is, two garbled circuit with the same multi encryption scheme and the same
	 * basic boolean circuit only differ in the garbled tables and translation table. <p>
	 * Thus we can hold one garbled circuit for all the circuits and only replace the garbled tables (and translation tables if necessary).
	 * The advantage is that the size of the tables only is much smaller that all the information stored in the circuit (gates and other 
	 * member variables). The size becomes important when sending large circuits.<p>
	 * The receiver of the circuits will set the garbled tables for the relevant circuit.
	 */
	public void setGarbledTables(byte[][] garbledTables);
	
	/**
     * Returns the translation table of the circuit. <P>
     * This is necessary since the constructor of the circuit may want to pass the translation table to other party. <p>
     * Usually, this will be used when the other party (not the constructor of the circuit) creates a circuit, sets the garbled tables 
     * and needs the translation table as well to complete the construction of the circuit.
     * @return the translation table of the circuit.  
     */
	public HashMap<Integer, Byte> getTranslationTable();
  
	/**
	 * Sets the translation table of the circuit. <p>
	 * This is necessary when the garbled tables where set and we would like to compute the circuit later on. 
	 * @param translationTable. This value should match the garbled tables of the circuit.
	 */
	public void setTranslationTable(HashMap<Integer, Byte> translationTable);
	
	/**
	 * @param partyNumber the number of the party which we need his input labels.
	 * @return an List containing the integer labels of the input wires of the given party number.
	 * @throws NoSuchPartyException 
	 */
	public List<Integer> getInputWireLabels(int partyNumber) throws NoSuchPartyException;

	/**
	 * @param partyNumber the number of the party which we need his number of inputs.
	 * @return the number of inputs of this circuit.
	 * @throws NoSuchPartyException 
	 */
	public int getNumberOfInputs(int partyNumber) throws NoSuchPartyException ;  
}
