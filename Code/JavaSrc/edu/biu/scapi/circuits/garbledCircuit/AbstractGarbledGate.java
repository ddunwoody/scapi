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

/**
 * {@code AbstractGarbledGate} is an abstract class that implements the standard
 * fields and methods that most garbled gates will share. Most optimizations
 * affect only the constructor, and the {@code compute}, and {@code verify}
 * methods. All garbled gate implementations should extend this class.
 * 
 * @author Steven Goldfeder
 * 
 */
public abstract class AbstractGarbledGate implements GarbledGate {

	private static final long serialVersionUID = -2772012685011270828L;
/**
   * An array containing the integer labels of the input Wire Labels to this
   * gate. The order of the {@code GarbledWire}s in this array is significant as
   * not all functions are symmetric.
   */
  /*
   * Note that the ordering of these Wires must be the same also since some
   * functions are not symmetric. For example consider the function ~y v x and
   * the following truth table: 
   *  x y  ~y v x 
   *  0 0    1
   *  0 1    0 
   *  1 0    1
   *  1 1    1
   */
  protected int[] inputWireLabels;
  /**
   * An array containing the integer labels of the output {@code GarbledWire}(s)
   */
  protected int[] outputWireLabels;
  /**
   * The number of input {@code GarbledWire}s to this {@code StandardGarbledGate}
   */
  protected int numberOfInputs;
  /**
   * The number of output {@code GarbledWire}s to this {@code StandardGarbledGate}.There
   * will generally be a single output {@code GarbledWire}. However in instances
   * in which fan-out of the output {@code GarbledWire} is >1, we left the
   * option for treating this as multiple {@code GarbledWire}s
   */
  protected int numberOfOutputs;
 
  /**
   * The integer label of this {@code FreeXORGarbledGate}. This label is used to
   * order {@code FreeXORGarbledGate}s in a {@link FreeXORGarbledBooleanCircuit}
   */
  protected int gateNumber;

  @Override
  public int[] getInputWireLabels() {
    return inputWireLabels;
  }

  @Override
  public int[] getOutputWireLabels() {
    return outputWireLabels;
  }
}
