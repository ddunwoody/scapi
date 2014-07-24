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
import java.security.InvalidKeyException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.Wire;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;

/**
 * {@code GarbledBooleanCircuit} is a general interface for all basic garbled circuits. It is implemented by all garbled circuits--optimized or not. <p>
 * All garbled circuits have four main operations: <p>
 * 1. The {@link #garble()} function that generates the keys and creates the garbled tables. <p>
 * 2. The {@link #compute()} function computes a result on a garbled circuit whose input has been set. <p>
 * 3. The {@link #verify(BooleanCircuit, Map)} method is used in the case of a malicious adversary to verify that the garbled circuit 
 * created is an honest garbling of the agreed upon non garbled circuit. For example, the constructing party constructs many garbled circuits and
 * the second party chooses all but one of them to verify and test the honesty of the constructing party.<p>
 * 4. The {@link #translate(Map)} that translates the garbled output from {@link #compute()} into meaningful output.<p>
 * 
 * @author Steven Goldfeder
 * 
 */
public interface GarbledBooleanCircuit {
	
	/**
	 * This method generates both keys for each wire. Then, creates the garbled table according to those values.<p>
	 * @return CircuitCreationValues contains both keys for each input and output wire and the translation table.
	 */
	public CircuitCreationValues garble();
	
	/**
	 * This method generates both keys for each input wire using the seed. 
	 * It then creates the garbled table according to those values.<p>
	 * @param seed Used to initialize the gprg.
	 * @return CircuitCreationValues Contains both keys for each input and output wire and the translation table.
	 * @throws InvalidKeyException In case the seed is an invalid key for the given PRG.
	 */
	public CircuitCreationValues garble(byte[] seed) throws InvalidKeyException;
		
	/**
	 * This method sets the input of the circuit. <p>
	 * It takes as a parameter a {@code Map} that maps the input wire indices to a garbled wire containing the appropriate garbled values. <p>
	 * See {@link #setGarbledInputFromUngarbledInput(File, Map)} for an alternate way of setting the input.
	 * @param presetInputWires A {@code Map} containing the input wires that have been preset with their values.
  	 */
	public void setInputs(Map<Integer, GarbledWire> presetInputWires) ;

	/**
	 * This method takes a map containing the {@code GarbledWire} indices and <b> non garbled</b> value. <p>
	 * This method then performs the lookup on the accompanying allInputWireValues {@code Map} and sets the inputs 
	 * to the corresponding garbled outputs.
	 * @param ungarbledInput A map containing the {@code GarbledWire} indices and <b> non garbled</b> value for that index. 
	 * @param allInputWireValues The map containing both garbled values for each input wire.
	 */
	public void setGarbledInputFromUngarbledInput(Map<Integer, Byte> ungarbledInput, Map<Integer, SecretKey[]> allInputWireValues) ;
 
	/**
	 * This method computes the circuit if the input has been set. <p>
	 * It returns a {@code HashMap} containing the garbled output. This output can be translated via the {@link #translate(Map)} method.
	 * @return returns a {@code HashMap} that maps the index of the output wire to the garbled value of the wire.
	 * @throws NotAllInputsSetException if not all the input has been set.
	 */
	public HashMap<Integer, GarbledWire> compute() throws NotAllInputsSetException;

	/**
     * The verify method is used in the case of malicious adversaries.<p>
     * Alice constructs n circuits and Bob can verify n-1 of them (of his choice) to confirm that they are indeed garbling of the 
     * agreed upon non garbled circuit. In order to verify, Alice has to give Bob both keys for each of the input wires.
     * @param allInputWireValues A {@Map} containing both keys for each input wire.
     * For each input wire , the map contains an array of two values. The value in the 0 position is the 0 encoding, and the
     * value in the 1 position is the 1 encoding.
     * @return {@code true} if this {@code GarbledBooleanCircuit} is a garbling the given keys, {@code false} if it is not.
     */
	public boolean verify(Map<Integer, SecretKey[]> allInputWireValues) ;

	/**
     * This function behaves exactly as the verify(Map<Integer, SecretKey[]> allInputWireValues) method except the last part.
     * The verify function verifies that the translation table matches the resulted output garbled values, while this function does not check it 
     * but return the resulted output garbled values. 
     * @param allInputWireValues A {@Map} containing both keys for each input wire.
     * For each input wire index, the map contains an array of two values. The value in the 0 position is the 0 encoding, and the
     * value in the 1 position is the 1 encoding.
     * @param allOutputWireValues A {@Map} containing both keys for each output wire. 
     * When calling the function this map should be empty and will be filled during the process of the function.
     * @return {@code true} if this {@code GarbledBooleanCircuit} is a garbling the given keys, {@code false} if it is not.
     */
	public boolean internalVerify(Map<Integer, SecretKey[]> allInputWireValues, Map<Integer, SecretKey[]> allOutputWireValues);
	
	/**
	 * Translates the garbled output obtained from the {@link #compute()} function into a meaningful(i.e. 0-1) output.<p>
	 * @param garbledOutput A {@code Map) that contains the garbled output. This map maps the output wire indices to {@code GarbledWire}s
	 * @return a {@code Map} that maps the output wire  to ungarbled {@code Wire}s that are set to either 0 or 1.
	 */
	public Map<Integer, Wire> translate(Map<Integer, GarbledWire> garbledOutput);
	
	/**
	 * Verifies that the given garbledOutput is valid values according to the given all OutputWireValues. <p>
	 * Meaning, for each output wire, checks that the garbled wire is one of the two possibilities.
	 * Then, translates the garbled output obtained from the {@link #compute()} function into a meaningful(i.e. 0-1) output.<p>
	 * @param garbledOutput A {@code Map) that contains the garbled output. This map maps the output wire s to {@code GarbledWire}s
	 * @param allOutputWireValues both values for each output wire.
	 * @return a {@code Map} that maps the output wire indices to ungarbled {@code Wire}s that are set to either 0 or 1.
	 * @throws CheatAttemptException if there is a garbledOutput values that is not one of the two possibilities.
	 */
	public Map<Integer, Wire> verifiedTranslate(Map<Integer, GarbledWire> garbledOutput, Map<Integer, SecretKey[]> allOutputWireValues) throws CheatAttemptException;

	
	/**
	 * The garbled tables are stored in the circuit for all the gates. This method returns the garbled tables. <p>
	 * This function is useful if we would like to pass many garbled circuits built on the same boolean circuit. <p>
	 * This is a compact way to define a circuit, that is, two garbled circuit with the same multi encryption scheme and the same
	 * basic boolean circuit only differ in the garbled tables and the translation table. <p>
	 * Thus we can hold one garbled circuit for all the circuits and only replace the garbled tables (and the translation tables if 
	 * necessary). The advantage is that the size of the tables only is much smaller that all the information stored in the circuit 
	 * (gates and other member variables). The size becomes important when sending large circuits.
	 * 
	 */
	public GarbledTablesHolder getGarbledTables();
	
	/**
	 * Sets the garbled tables of this circuit.<p>
	 * This function is useful if we would like to pass many garbled circuits built on the same boolean circuit. <p>
	 * This is a compact way to define a circuit, that is, two garbled circuit with the same multi encryption scheme and the same
	 * basic boolean circuit only differ in the garbled tables and the translation table. <p>
	 * Thus we can hold one garbled circuit for all the circuits and only replace the garbled tables (and the translation tables if necessary).
	 * The advantage is that the size of the tables only is much smaller that all the information stored in the circuit (gates and other 
	 * member variables). The size becomes important when sending large circuits.<p>
	 * The receiver of the circuits will set the garbled tables for the relevant circuit.
	 */
	public void setGarbledTables(GarbledTablesHolder garbledTables);
	
	/**
     * Returns the translation table of the circuit. <P>
     * This is necessary since the constructor of the circuit may want to pass the translation table to an other party. <p>
     * Usually, this will be used when the other party (not the constructor of the circuit) creates a circuit, sets the garbled tables 
     * and needs the translation table as well to complete the construction of the circuit.
     * @return the translation table of the circuit.  
     */
	public HashMap<Integer, Byte> getTranslationTable();
  
	/**
	 * Sets the translation table of the circuit. <p>
	 * This is necessary when the garbled tables where set and we would like to compute the circuit later on. 
	 * @param translationTable This value should match the garbled tables of the circuit.
	 */
	public void setTranslationTable(HashMap<Integer, Byte> translationTable);
	
	/**
	 * Returns the input wires' indices of the given party.
	 * @param partyNumber The number of the party which we need his input wire indices.
	 * @return a List containing the indices of the input wires of the given party number.
	 * @throws NoSuchPartyException In case the given party number is not valid.
	 */
	public List<Integer> getInputWireIndices(int partyNumber) throws NoSuchPartyException;
	
	/**
	 * @return an array containing the indices of the circuit's output wires.
	 */
	public int[] getOutputWireIndices();

	/**
	 * Returns the number of input wires of the given party.
	 * @param partyNumber the number of the party which we need his number of inputs.
	 * @return the number of inputs of this circuit.
	 * @throws NoSuchPartyException In case the given party number is not valid.
	 */
	public int getNumberOfInputs(int partyNumber) throws NoSuchPartyException; 
	
	/**
	 * Returns the number of parties using this circuit.
	 * 
	 */
	public int getNumberOfParties();
}
