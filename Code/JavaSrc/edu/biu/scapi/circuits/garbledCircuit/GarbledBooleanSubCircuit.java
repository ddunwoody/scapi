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
import java.io.FileNotFoundException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.util.List;
import java.util.Map;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.exceptions.CiphertextTooLongException;
import edu.biu.scapi.exceptions.InvalidInputException;
import edu.biu.scapi.exceptions.KeyNotSetException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;
import edu.biu.scapi.exceptions.PlaintextTooLongException;
import edu.biu.scapi.exceptions.TweakNotSetException;

/**
 * {@code GarbledBooleanSubCircuit} is a general interface implemented by all
 * garbled sub circuits and circuits--optimized or not. 
 * All garbled sub circuits have three main
 * functions. The construct function which is provided by the constructor of the
 * implementing classes. The {@link #compute()} function computes a result on a
 * garbled circuit that's input has been set. 
 * The {@link #verify(BooleanCircuit, Map)} method is used in the case of a
 * malicious adversary to verify that the garbled circuit created is an honest
 * garbling of the agreed upon non garbled) circuit. The constructing party
 * constructs many garbled circuits and the second party chooses all but one of
 * them to verify and test the honesty of the constructing party.
 * 
 * @author Steven Goldfeder
 * 
 */
public interface GarbledBooleanSubCircuit extends Serializable{
 
	/**
	   * This method computes the circuit if input has been set. If input has not
	   * been set it throws an exception. It returns a {@code Map} containing the
	   * garbled output. This output can be translated via the
	   * {@link #translate(Map)} method.
	   * 
	   * @return returns a {@code Map} that maps the label of the output wire to the
	   *         garbled value of the wire
	   * @throws InvalidKeyException
	   * @throws IllegalBlockSizeException
	   * @throws CiphertextTooLongException
	   * @throws KeyNotSetException
	   * @throws NotAllInputsSetException
	   * @throws TweakNotSetExceptioncomputed
	   *           {@code GarbledWire}
	   */

	  public Map<Integer, GarbledWire> compute() throws InvalidKeyException,
	      IllegalBlockSizeException, CiphertextTooLongException,
	      KeyNotSetException, TweakNotSetException, NotAllInputsSetException;

   /**
   * The verify method is used in the case of malicious adversaries. Alice
   * constructs n circuits and Bob can verify n-1 of them(of his choosing) to
   * confirm that they are indeed garblings of the agreed upon non garbled
   * circuit. In order to verify, Alice has to give Bob both garbled values for
   * each of the input wires.
   * 
   * @param ungarbledCircuit
   *          the circuit that this {@code GarbledBooleanCircuit} is supposed to
   *          be a garbling of. This is the circuit that Alice and Bob agreed
   *          upon in Yao's protocol. We are verifying that this
   *          {@code GarbledBooleanCircuit} is indeed a garbling of the agreed
   *          upon ungarbled circuit
   * @param allInputWireValues
   *          a {@Map} containing both garbled values for each input wire.
   *          For each input wire label, the map contains an array of two
   *          values. The value in the 0 position is the 0 encoding, and the
   *          value in the 1 position is the 1 encoding.
   * @return {@code true} if this {@code GarbledBooleanCircuit} is a garbling of
   *         the ungarbledCircuit, {@code false} if it is not
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws KeyNotSetException
   * @throws TweakNotSetException
   * @throws PlaintextTooLongException
   * @throws CiphertextTooLongException
   */
  public boolean verify(BooleanCircuit ungarbledCircuit,
      Map<Integer, SecretKey[]> allInputWireValues) throws InvalidKeyException,
      IllegalBlockSizeException, KeyNotSetException, TweakNotSetException,
      PlaintextTooLongException, CiphertextTooLongException;

  /**
   * This method sets the input for the specified party. It takes as a parameter a
   * {@code Map} that maps the input Wire labels to a garbled wire containing
   * the appropriate garbled values. See
   * {@link #setPartyOneGarbledInputFromUngarbledFile(File, Map)} for an
   * alternate way of setting the input.
   * 
   * @param presetInputWires
   *          a {@code Map} containing the input wires that have been preset
   *          with their values
   * @param partyNumber 
   *          1 to set the input for partyOne and 2 for PartyTwo
   * @throws NoSuchPartyException 
   * 
   */
  public void setInputs(Map<Integer, GarbledWire> presetInputWires, int partyNumber) throws NoSuchPartyException;

  /**
   * This method takes in a file containing the number of inputs for the specified party
   * followed by the {@code GarbledWire} label and <b> non garbled</b> value for
   * each wire. This method than performs the lookup on the accompanying
   * allInputWireValues {@code Map} and sets the inputs to the corresponding
   * garbled outputs.
   * 
   * @param f
   *          the file containing the number of input wire followed by a list of
   *          input wire labels and their garbled values for PartyOne
   * @param allInputWireValues
   *          the map containing both garbled values for each input wire
   * @param partyNumber
   *          1 to set the input for partyOne and 2 for PartyTwo
   * @throws FileNotFoundException
   * @throws NoSuchPartyException 
   * @throws InvalidInputException 
   */
  public void setGarbledInputFromUngarbledFile(File f,
      Map<Integer, SecretKey[]> allInputWireValues,int partyNumber)
      throws FileNotFoundException, NoSuchPartyException, InvalidInputException;


 
  /**
   * @param partyNumber  1 for partyOne and 2 for PartyTwo
   * @return an List containing the integer labels of the input wires for the specified party
   * @throws NoSuchPartyException 
   */
  public List<Integer> getInputWireLabels(int partyNumber) throws NoSuchPartyException;

  /**
   * @param partyNumber  1 for partyOne and 2 for PartyTwo
   * @return the number of inputs for the specified party
   * @throws NoSuchPartyException 
   */
  public int getNumberOfInputs(int partyNumber) throws NoSuchPartyException;  
  
  /**
   * This is package private since it is only for the classes in the package like the gates.
   * @return the MultiKeyEncryptionScheme used in the garbled circuit.  
   * 
   */
  public MultiKeyEncryptionScheme getMultiKeyEncryptionScheme();
  
  /**
   * The garbled tables are stored in the circuit for all the gates. 
   * returns the garbled tables.
   * 
   * This function is useful if we would like to pass many garbled circuits built on the same boolean circuit. 
   * This is a compact way to define a circuit, that is, two garbled circuit with the same multi encryption scheme and the same
   * basic boolean circuit only differ in the garbled tables (and translation table for circuits that are not only sub circuits). 
   * Thus we can hold one garbled circuit for all the circuits and only replace the garbled tables (and translation tables if nessecary).
   * The advantage is that the size of the tables only is much smaller that all the information stored in the circuit (gates and other 
   * member variables). The size becomes important when sending large circuits.
   * The creator of the circuits will use this function to get the tables of the relevant circuit.
   * 
   */
  public byte[][] getGarbledTables();
  
  
  /**
   * Sets the garbled tables of this circuit.
   * This function is useful if we would like to pass many garbled circuits built on the same boolean circuit. 
   * This is a compact way to define a circuit, that is, two garbled circuit with the same multi encryption scheme and the same
   * basic boolean circuit only differ in the garbled tables (and translation table for circuits that are not only sub circuits). 
   * Thus we can hold one garbled circuit for all the circuits and only replace the garbled tables (and translation tables if nessecary).
   * The advantage is that the size of the tables only is much smaller that all the information stored in the circuit (gates and other 
   * member variables). The size becomes important when sending large circuits.
   * The receiver of the circuits will set the garbled tables for the relevant circuit.
   */
  
  public void setGarbledTables(byte[][] garbledTables);

}
