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
import java.util.Map;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.Gate;
import edu.biu.scapi.circuits.encryption.CiphertextTooLongException;
import edu.biu.scapi.circuits.encryption.KeyNotSetException;
import edu.biu.scapi.circuits.encryption.TweakNotSetException;

/**
 * An interface that {@link StandardGarbledGate}'s and any specialized or
 * optimized garbled gate will implement. This will allow the correct method to
 * be caused in cases in which we are dealing with different types of optimized
 * Gates. For example, say that we are using the Free-XOR technique. In this
 * case, we will have a mixture of {@link StandardGarbledGate}s and
 * {@link FreeXORGate}s. We will use this interface so that we can access both
 * of them without knowing ahead of time which one we will be given.
 * 
 * @author Steven Goldfeder
 * 
 */
public interface GarbledGate {
  /**
   * The compute method computes the output of this gate and sets the output
   * wire(s) to that value
   * 
   * @param computedWires
   *          A {@link Map} containing the {@link GarbledWires}s that have
   *          already been computed and had their values set
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws CiphertextTooLongException
   * @throws KeyNotSetException
   * @throws TweakNotSetException
   */

  public void compute(Map<Integer, GarbledWire> computedWires)
      throws InvalidKeyException, IllegalBlockSizeException,
      CiphertextTooLongException, KeyNotSetException, TweakNotSetException;

  /**
   * This method tests an ungarbled {@link Gate} for equality to this
   * {@code GarbledGate} returning {@code true} if they are equal and
   * {@code false} otherwise. It is called verify since in general, when this
   * method is used, the assumption is that they are equal and we are verifying
   * this assumption.
   * 
   * @param g
   *          an ungarbled {@code Gate} to be tested for equality to this
   *          {@code GarbledGate}
   * @return returns {@code true} if the gates are have the same truth table and
   *         label, and {@code false} otherwise
   *          * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws CiphertextTooLongException
   * @throws KeyNotSetException
   * @throws TweakNotSetException
   */
  boolean verify(Gate g, Map<Integer, SecretKey[]> allWireValues)
      throws InvalidKeyException, IllegalBlockSizeException,
      CiphertextTooLongException, KeyNotSetException, TweakNotSetException;

  /**
   * @return an array containing the integer labels of the gate's input wires.
   */
  public int[] getInputWireLabels();

  /**
   * @return an array containing the integer labels of the gate's output wires.
   *         generally this will be a single wire, but if fan-out >1 a circuit
   *         designer may label it as multiple wires.
   */
  public int[] getOutputWireLabels();
}
