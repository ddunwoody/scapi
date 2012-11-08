/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
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
import java.security.InvalidKeyException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.Wire;
import edu.biu.scapi.circuits.encryption.CiphertextTooLongException;
import edu.biu.scapi.circuits.encryption.KeyNotSetException;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.circuits.encryption.TweakNotSetException;

/**The {@code AbstractGarbledBooleanCircuit} class is an abstract representation of a circuit. It contains all of the methods that are 
 * standard to all implementations and are not generally affected by optimizations. 
 * @author Steven Goldfeder
 *
 */
public abstract class AbstractGarbledBooleanCircuit implements GarbledBooleanCircuit {

  protected int[] inputWireLabels;
  protected int[] outputWireLabels;
  protected boolean isInputSet = false;
  protected int numberOfWires;
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
  protected Map<Integer, Integer> translationTable;
  /**
   * The garbled gates of this garbled circuit
   */
  GarbledGate[] gates;
  /**
   * A map that is used during computation to map a {@code GarbledWire}'s label to the computed and set {@code GarbledWire}
   */
  Map<Integer, GarbledWire> computedWires;
  /**
   * The encryption scheme that will use to garble,compute, and verify this circuit
   */
  MultiKeyEncryptionScheme mes;

  public Map<Integer, GarbledWire> compute() throws InputNotSetException,
      InvalidKeyException, IllegalBlockSizeException,
      CiphertextTooLongException, KeyNotSetException, TweakNotSetException {
    if (!isInputSet) {
      throw new InputNotSetException();
    }
    /*we use the interface GarbledGate and thus this works for all implementing classes. The verify method of the
     * specific garbled gate being used will be called. This allows us to have circuits with different types of gates {i.e a FreeXORGarbledBooleanCircuit
     * contains both StandardGarbledGates and FreeXORGates) and this will work for all the gates
     */
    
    for (GarbledGate g : gates) {
      g.compute(computedWires);
    }
    /*copy only the values that we need to retain--i.e. the values of the output wires to a 
     * new map to be returned. The computedWire's map contains more values than we need to retain as it has values for all wires, not only circuit output wires
     */
    Map<Integer, GarbledWire> garbledOutput = new HashMap<Integer, GarbledWire>();
    for (int w : outputWireLabels) {
      garbledOutput.put(w, computedWires.get(w));
    }

    return garbledOutput;
  }

  /*
   * We implemented two different translates. The one currently being used creates Wires and thus has the 
   * benefit of being uniform with our regular (nongarbled) circuit implementation.
   */
  public Map<Integer, Wire> translate(Map<Integer, GarbledWire> garbledOutput) {
    Map<Integer, Wire> translatedOutput = new HashMap<Integer, Wire>();
    for (int w : outputWireLabels) {
      int signalBit = translationTable.get(w);
      int permutationBitOnWire = garbledOutput.get(w).getSignalBit();
      int value = signalBit ^ permutationBitOnWire;
     // System.out.print(value);
      Wire translated = new Wire(value);
      translatedOutput.put(w, translated);
    }
    //System.out.println("");
    return translatedOutput;

  }

  /*
   * Map<Integer, Integer> translate() {
   *  Map<Integer, Integer> translatedOutput = new HashMap<Integer, Integer>();
   *  for(int w : outputWireLabels){
   * translatedOutput.put(w, translationTable.get(computedWires.get(w))); }
   * return translatedOutput;
   * }
   */

  public boolean verify(BooleanCircuit ungarbledCircuit,
      Map<Integer, SecretKey[]> allInputWireValues) throws InvalidKeyException,
      IllegalBlockSizeException, CiphertextTooLongException,
      KeyNotSetException, TweakNotSetException {
    // First we check that the number of gates is the same
    if (gates.length != ungarbledCircuit.getGates().length) {
      return false;
    }
    /*
     * Next we check gate by gate that the garbled Gate's truth table is
     * consistent with the ungarbled gate's truth table. We say consistent since
     * the gate's verify method checks the following: everywhere that the
     * ungarbled gate's truth table has a 0, there is one encoding, and wherever
     * it has a 1 there is a second encoding. Yet, under this method a 0001
     * truth table would be consistent with a 1000 truth table as we have no
     * knowledge of what the encoded values actually translate to. Thus, we test
     * for consistent and we assume that the encoded value corresponding to 0 is
     * a 0, and that the value that corresponds to 1 is a 1. Based on this
     * assumption, we map the output wire to the 0-encoded value and 1-encoded
     * value. Thus if our assumption is wrong, the next gate may not verify
     * correctly. We continue this process until we reach the circuit output
     * wires. At this point we confirm(or reject) all assumption by checking the
     * translation table and seeing if the wire we expected to encode to a 0 was
     * actually a 0 and the 1 was a 1. Once we have done this, we have verified
     * the circuits are identical and have not relied on any unproven
     * assumptions.
     */

    /*
     * we are going to need to add values for non-input wires to the map as we
     * compute them(this will take place in the Gate's verify method that we are
     * about to call. In order to not change the input Map, we first copy its
     * contents to a new Map
     */
    Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
    allWireValues.putAll(allInputWireValues);
    for (int i = 0; i < gates.length; i++) {
      if (gates[i].verify(ungarbledCircuit.getGates()[i], allWireValues) == false) {
        return false;
      }
    }
    /*
     * The last step as we mentioned above is to check that the output wires
     * translate correctly. At this point, we have gone through the entire
     * circuit so allWireValues now contains both possible values for every wire
     * in the circuit. We check the output wire values and make sure that the
     * 0-wire translates to a 0 and that the 1 wire translates to a 1.
     */
    for (int w : outputWireLabels) {
      SecretKey zeroValue = allWireValues.get(w)[0];
      SecretKey oneValue = allWireValues.get(w)[1];

      int signalBit = translationTable.get(w);
      int permutationBitOnZeroWire = (zeroValue.getEncoded()[zeroValue
          .getEncoded().length - 1] & 1) == 0 ? 0 : 1;
      int permutationBitOnOneWire = (oneValue.getEncoded()[oneValue
          .getEncoded().length - 1] & 1) == 0 ? 0 : 1;
      int translatedZeroValue = signalBit ^ permutationBitOnZeroWire;
      int translatedOneValue = signalBit ^ permutationBitOnOneWire;
      if (translatedZeroValue != 0 || translatedOneValue != 1) {
        return false;
      }
    }

    return true;
  }

  /**
   * Given a file containing the number of inputs and then the
   * {@code GarbledWire} label followed by a 0 or a 1, this method will look up
   * the garbled encoding of the 0 or 1 for that {@code GarbledWire} in the
   * provided {@code Map} and set the inputs to the appropriate corresponding
   * garbled values
   * 
   * @param f
   *          the {@code File} containing the input values (not garbled--i.e. 0
   *          or 1)
   * @param allWireValues
   *          a {@code Map} that maps each input {@code GarbledWire} to an array
   *          containing its 0 and 1 {@code SecretKey} garbled values.
   * @throws FileNotFoundException
   *           {@code throws} this exception if the file is not found in the
   *           specified directory
   */

  public void setGarbledInputFromUngarbledFile(File f,
      Map<Integer, SecretKey[]> allInputWireValues)
      throws FileNotFoundException {
    Scanner s = new Scanner(f);
    Map<Integer, GarbledWire> inputs = new HashMap<Integer, GarbledWire>();
    int numberOfInputs = s.nextInt();
    for (int i = 0; i < numberOfInputs; i++) {
      int label = s.nextInt();
      inputs.put(label,
          new GarbledWire(label, allInputWireValues.get(label)[s.nextInt()]));
    }
    setInputs(inputs);
  }

  public void setInputs(Map<Integer, GarbledWire> presetInputWires) {
    computedWires = presetInputWires;
    isInputSet = true;
  }
}
