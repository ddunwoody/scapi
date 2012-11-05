/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
package edu.biu.scapi.circuits.garbledCircuit;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.util.Map;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.Wire;
import edu.biu.scapi.circuits.encryption.CiphertextTooLongException;
import edu.biu.scapi.circuits.encryption.KeyNotSetException;
import edu.biu.scapi.circuits.encryption.PlaintextTooLongException;
import edu.biu.scapi.circuits.encryption.TweakNotSetException;

/**
 * {@code GarbledBooleanCircuit} is a general interface implemented by all
 * garbled circuits--optimized or not. All garbled circuits have four main
 * functions. The construct function which is provided by the constructor of the
 * implementing classes. The {@link #compute()} function computes a result on a
 * garbled circuit that's input has been set. The {@link #translate(Map)} method
 * translates the garbled output from {@link #compute()} into meaningful
 * output. The {@link #verify(BooleanCircuit, Map)} method is used in the case
 * of a malicious adversary to verify that the garbled circuit created is an
 * honest garbling of the agreed upon non garbled) circuit. The constructing
 * party constructs many garbled circuits and the second party chooses all but
 * one of them to verify and test the honesty of the constructing party.
 * 
 * @author Steven Goldfeder
 * 
 */
public interface GarbledBooleanCircuit {
  /**
   * This method computes the circuit if input has been set. If input has not
   * been set it throws an exception. It returns a {@code Map} containing the
   * garbled output. This output can be translated via the
   * {@link #translate(Map)} method.
   * 
   * @return returns a {@code Map} that maps the label of the output wire to the garbled value of the wire
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws CiphertextTooLongException
   * @throws KeyNotSetException
   * @throws InputNotSetException
   * @throws TweakNotSetExceptioncomputed
   *           {@code GarbledWire}
   */

  public Map<Integer, GarbledWire> compute() throws InvalidKeyException,
      IllegalBlockSizeException, CiphertextTooLongException,
      KeyNotSetException, TweakNotSetException, InputNotSetException;

  /**
   * Translates the garbled output obtained from the {@link #compute()} function
   * into meaningful(i.e. 0-1) output.
   * 
   * @param garbledOutput
   *          a {@code Map) that containing the garbled output. This map maps
   *          the output wire labels to {@code GarbledWire}s
   * @return a {@code Map} that maps the output wire labels to ungarbled
   *         {@code Wire}s that are set to either 0 or 1.
   */
  public Map<Integer, Wire> translate(Map<Integer, GarbledWire> garbledOutput);

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
   * This method sets the input. It takes as a parameter a {@code Map} that maps
   * the input Wire labels to a garbled wire containing the appropriate garbled
   * value. See {@link #setGarbledInputFromUngarbledFile(File, Map)} for an
   * alternate way of setting the input.
   * 
   * @param presetInputWires
   *          a {@code Map} containing the input wires that have been preset
   *          with their values
   */
  public void setInputs(Map<Integer, GarbledWire> presetInputWires);

  /**
   * This method takes in a file containing the number of inputs followed by the
   * {@code GarbledWire} label and <b> non garbled</b> value for each wire. This
   * method than performs the lookup on the accompanying allInputWireValues
   * {@code Map} and sets the inputs to the corresponding garbled outputs.
   * 
   * @param f
   *          the file containing the number of input wire followed by a list of
   *          input wire labels and their garbled values
   * @param allInputWireValues
   *          the map containing both garbled values for each input wire
   * @throws FileNotFoundException
   */
  public void setGarbledInputFromUngarbledFile(File f,
      Map<Integer, SecretKey[]> allInputWireValues)
      throws FileNotFoundException;
}
