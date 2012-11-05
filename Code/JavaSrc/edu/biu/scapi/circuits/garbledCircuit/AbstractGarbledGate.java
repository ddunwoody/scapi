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
