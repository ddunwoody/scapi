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
import java.io.Serializable;
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
 * A software representation of a boolean circuit. The circuit is constructed
 * from {@code Wire}s and {@code Gate}s. Once input has been set, the compute()
 * function performs the computation and returns the computed output
 * {@code Wire}s. The verify function verifies that two gates are equivalent.
 * 
 * @author Steven Goldfeder
 * 
 */

public class BooleanCircuit implements Serializable {

	private static final long serialVersionUID = -4658751288524308910L;

/**
   * An array of boolean flags set to {@code true} if and only if the input has been set for the indexed party or the indexed party has no inputs
   */
  private boolean[] isInputSet;
  
  /**
   * A {@code Map} that maps the integer label of a {@code Wire} to the
   * previously set {@code Wire}. Only {@code Wire}s whose value has been set
   * will be on this map.
   * 
   */
  Map<Integer, Wire> computedWires = new HashMap<Integer,Wire>();
  /**
   * An array of the {@code Gate}s of this {@code BooleanCircuit} sorted
   * topologically.
   */
  private Gate[] gates;
  /**
   * * An array containing the integer labels if the input {@code Wire}s of this
   * {@code BooleanCircuit}
   */
  private int[] outputWireLabels;
  /**
   * The total number of {@code Wire}s in the circuit
   */
  private int numberOfWires;
  
  /**
   * The number of parties that are interacting(i.e. receiving input and/or output) with this circuit
   */
  private int numberOfParties;  
  /**
   * An arrayList containing the integer labels of the input {@code Wire}s of this
   * {@code BooleanCircuit} indexed by the party number.
   */
  private ArrayList<ArrayList<Integer>> eachPartysInputWires = new ArrayList<ArrayList<Integer>>();

  // Integer.parseInt(s.next()) is significantly faster than s.nextInt() so I
  // use the former
  /**
   * Constructs a BooleanCircuit from a File. The File first lists the number of
   * {@code Gate}s, then the number of {@code Wire}s, number of input Wires and
   * following this is the integer label of each of these input {@code Wire}
   * s.Next it lists the number of output {@code Wire}s followed by the integer
   * label of each of these {@code Wires}. Then for each gate, we have the
   * following: #inputWires #numberOutputWires inputWireLabels OutputWireLabels
   * truth Table(as a 0-1 string): example file: 1 3 2 433 437 1 566 2 1 433 437
   * 566 0001
   * <p>
   * Note that we parse the File and delimit on whitespace or new lines, so the
   * line breaks are treated no differently than a single space.
   * </p>
   * 
   * @param f
   *          the {@link File} from which the circuit is read.
   * @throws FileNotFoundException
   *           if f is not found in the specified directory.
   * @throws CircuitFileFormatException 
   */
  public BooleanCircuit(File f) throws FileNotFoundException, CircuitFileFormatException {
    Scanner s = new Scanner(f);
    int numberOfGates = Integer.parseInt(s.next());
    gates = new Gate[numberOfGates];
    numberOfWires = Integer.parseInt(s.next());
    numberOfParties =  Integer.parseInt(s.next());
    isInputSet = new boolean[numberOfParties];
    for (int i = 0; i < numberOfParties; i++) {
      if (Integer.parseInt(s.next()) != i+1) {//add 1 since parties are indexed from 1, not 0
        throw new CircuitFileFormatException();
      }
      int numberOfInputsForCurrentParty = Integer.parseInt(s.next());
      if(numberOfInputsForCurrentParty < 0){
        throw new CircuitFileFormatException();
      }
      boolean isThisPartyInputSet = numberOfInputsForCurrentParty ==0? true : false;
      isInputSet[i]=isThisPartyInputSet;
      ArrayList<Integer> currentPartyInput = new ArrayList<Integer>();
      eachPartysInputWires.add(currentPartyInput);
      for (int j = 0; j < numberOfInputsForCurrentParty; j++) {
        currentPartyInput.add(Integer.parseInt(s.next()));
      }
    }
 /*
     * The ouputWireLabels are the outputs from this circuit. However, this
     * circuit may actually be a single layer of a larger layered circuit. So
     * this output can be part of the input to another layer of the circuit.
     */
    int numberOfCircuitOutputs = Integer.parseInt(s.next());
    outputWireLabels = new int[numberOfCircuitOutputs];
    for (int i = 0; i < numberOfCircuitOutputs; i++) {
      outputWireLabels[i] = Integer.parseInt(s.next());
    }
    for (int i = 0; i < numberOfGates; i++) {
      int numberOfGateInputs = Integer.parseInt(s.next());
      int numberOfGateOutputs = Integer.parseInt(s.next());
      int[] inputWireLabels = new int[numberOfGateInputs];
      int[] outputWireLabels = new int[numberOfGateOutputs];
      for (int j = 0; j < numberOfGateInputs; j++) {
        inputWireLabels[j] = Integer.parseInt(s.next());
      }
      for (int j = 0; j < numberOfGateOutputs; j++) {
        outputWireLabels[j] = Integer.parseInt(s.next());
      }
      /*
       * //This code uses an integer representation of a truth table instead of
       * a BitSet representation. int truthTable = s.nextInt(2); Gates()[i] =
       * new Gate(i,truthTable, inputWireLabels, outputWireLabels); }
       */

      /*
       * We create a BitSet representation of the truth table from the 01 String
       * that we read from the file.
       */
      BitSet truthTable = new BitSet();
      String tTable = s.next();
      for (int j = 0; j < tTable.length(); j++) {
        if (tTable.charAt(j) == '1') {
          truthTable.set(j);
        }
      }
      // we now construct the gate
      gates[i] = new Gate(i, truthTable, inputWireLabels, outputWireLabels);
    }

  }

  /**
   * Constructs a {code Booleancircuit} from an array of gates. Each gates keeps
   * an array of the labels of its inpout and ouput wires. The constructor is
   * provided with a list of which {@link Wire}s are output {@link Wire}s of the
   * {@code BooleanCircuit}.
   * 
   * @param gates
   *          an array of {@link Gate}s to create from which to construct the
   *          {@code BooleanCircuit}
   * @param outputWireLabels
   *          an array containing the labels of the wires that will be ouput of
   *          the {@code BooleanCircuit}
   */
  public BooleanCircuit(Gate[] gates, int[] outputWireLabels) {
    this.gates = gates;
    this.outputWireLabels = outputWireLabels;
  }

    /**
   * Sets the specified party's input to the circuit from a map containing constructed and set
   * {@link Wire}s. It updates that this party's input has been set. Once the input is set for all parties that have input, the circuit is ready to be computed.
   * 
   * @param presetInputWires
   *          the circuit's input Wires whose values have been previously set
     * @throws NoSuchPartyException 
   */
  void setInputs(Map<Integer, Wire> presetInputWires,int partyNumber) throws NoSuchPartyException {
    if(partyNumber < 1 || partyNumber > numberOfParties){
      throw new NoSuchPartyException();
    }
    computedWires.putAll(presetInputWires);
    isInputSet[partyNumber-1]=true;
  }

  /**
   * Sets the input to the circuit by reading it from a file. Written in the
   * file is a list that contains the number of input {@link Wire}s followed by
   * rows of {@link Wire} numbers and values.
   * 
   * @param inputWires
   *          the {@link File} containing the representation of the circuit's
   *          input
   * @throws FileNotFoundException
   * @throws InvalidInputException 
   * @throws NoSuchPartyException 
   */
  public void setInputs(File inputWires, int partyNumber) throws FileNotFoundException, InvalidInputException, NoSuchPartyException {
    if(partyNumber < 1 || partyNumber > numberOfParties){
      throw new NoSuchPartyException();
    }
    Scanner s = new Scanner(inputWires);
    int numberOfInputWires = s.nextInt();
    if(numberOfInputWires != getNumberOfInputs(partyNumber)){
      throw new InvalidInputException();
    }
    Map<Integer, Wire> presetInputWires = new HashMap<Integer, Wire>();
    //could include error checking here to make sure the wires are correct, but would slow down setInput considerably
    for (int i = 0; i < numberOfInputWires; i++) {
      int wireLabel = s.nextInt();
      presetInputWires.put(wireLabel, new Wire(s.nextInt()));
    }
    setInputs(presetInputWires,partyNumber);
  }

  /**
   * Computes the circuit if the input has been set.
   * 
   * @return a {@link Map} that maps the output {@link Wire} label to the
   *         computed {@link Wire}
   * @throws NotAllInputsSetException 
   */
  public Map<Integer, Wire> compute() throws NotAllInputsSetException {
    for (int i = 0; i < numberOfParties; i++) {
      if (!isInputSet[i]) {
        throw new NotAllInputsSetException();
      }
    }
      /*   computes each Gate. Since the Gates are provided in topological order, by
     the time the compute function on a given Gate is called, its input Wires
     will have already been assigned values*/
    for (Gate g : getGates()) {
      g.compute(computedWires);
    }
    /*
     * The computedWires array contains all the computed wire values--even those
     * that it is no longer necessary to retain.So, we create a new Map called
     * outputMap which only stores the Wires that are output Wires to the
     * circuit. We return outputMap.
     */
    Map<Integer, Wire> outputMap = new HashMap<Integer, Wire>();
    for (int w : outputWireLabels) {
      outputMap.put(w, computedWires.get(w));
    }
    return outputMap;
  }

  /**
   * The verify method tests the circuits for equality returning {@code true} if
   * they are and {@code false}if they are not. In order to be considered equal,
   * {@code Gate}s and {@code Wire}s must be labeled identically and
   * {@code Gate}s must contain the same truth table.
   * 
   * @param c
   *          a {@code BooleanCircuit} to be tested for equality to this
   *          {@code BooleanCircuit}
   * @return returns {@code true} if the given {@code BooleanCircuit} is
   *         equivalent to this {@code Boolean Circuit}, {@code false} otherwise
   */
  boolean verify(BooleanCircuit c) {
    // first tests to see that the number of Gates is the same for each circuit.
    // If it's not, then the two are not equal.
    if (getGates().length != c.getGates().length) {
      return false;
    }
    // Calls the verify method of the Gate class to compare each corresponding
    // Gate. If any of them return false, the circuits are not the same.
    for (int i = 0; i < getGates().length; i++) {
      if (getGates()[i].verify(c.getGates()[i]) == false) {
        return false;
      }
    }
    return true;
  }

  /**
   * 
   * @return an array of the {@link Gate}s of this circuit
   */
  public Gate[] getGates() {
    return gates;
  }

  /**
   * @return an array of the output{@link Wire} labels of this circuit
   */

  public int[] getOutputWireLabels() {
    return outputWireLabels;
  }

  /**
   * An accessor for the number of {@link Wire}s in this {@code BooleanCircuit}
   * 
   * @return the number of {@link Wire}as in the circuit
   */
  public int getNumberOfWires() {
    return numberOfWires;
  }

  /**
   * @param partyNumber the number of the party whose input wires will be returned
   * @return an ArrayList containing the input {@link Wire} labels of the specified party
   * @throws NoSuchPartyException 
   */
  
  public ArrayList<Integer> getInputWireLabels(int partyNumber) throws NoSuchPartyException {
    if(partyNumber < 1 || partyNumber > numberOfParties){
      throw new NoSuchPartyException();
    }
    //we subtract one from the party number since the parties are indexed beginning from one, but the ArrayList is indexed from 0
    return eachPartysInputWires.get(partyNumber-1);
  }
  
  /**
   * @param partyNumber the number of the party whose number of input wires will be returned
   * @return the number of input wires for the specified party
   * @throws NoSuchPartyException 
   */
  public int getNumberOfInputs(int partyNumber) throws NoSuchPartyException{
    if(partyNumber < 1 || partyNumber > numberOfParties){
      throw new NoSuchPartyException();
    }
    //we subtract one from the party number since the parties are indexed beginning from one, but the ArrayList is indexed from 0
    return eachPartysInputWires.get(partyNumber-1).size();
  }

  public int getNumberOfParties() {
    return numberOfParties;
  }
  }


