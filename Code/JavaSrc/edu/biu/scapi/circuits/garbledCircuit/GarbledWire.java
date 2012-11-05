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

import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.Wire;

/**
 * This class is a software representation a garbled Wire. Like, a standard
 * {@link Wire} in a non-garbled {@link BooleanCircuit}, a {@code GarbledWire}
 * can carry one of two values. However, these values, as its name suggests are
 * garbled meaning that the actual boolean value of the wire is encoded and
 * cannot be determined from the garbled value.
 * 
 * @author Steven Goldfeder
 * 
 */
public class GarbledWire {
  /**
   * The garbled value of this {@code GarbledWire}. The least significant bit is
   * the signal bit.
   */
  private SecretKey valueAndSignalBit;
  /**
   * The integer label of this {@code GarbledWire}
   */
  int label;

  /**
   * Constructs a {@code GarbledWire} and assigns it a label, value and
   * signalBit.
   * 
   * @param label
   *          the integer label of this {@code GarbledWire}
   * @param valueAndSignalBit
   *          a secretKey containing the {@code GarbledWire}'s garbled value.
   *          The least significant bit(of the underlying {@code byte[]} of the
   *          {@link SecretKey} is the signal bit.
   */
  public GarbledWire(int label, SecretKey valueAndSignalBit) {
    this.label = label;
    this.valueAndSignalBit = valueAndSignalBit;
  }

  /**
   * Constructor that constructs a {@code GarbledWire} but does not assign it a
   * label or a value/signal bit.
   */
  GarbledWire() {

  }

  /**
   * @return a SecretKey containing the garbled value of this
   *         {@code GarbledWire}, and the least significant bit of the
   *         underlying {@code byte[]} is the signal bit.
   */
  public SecretKey getValueAndSignalBit() {
    return valueAndSignalBit;
  }

  /**
   * @return the integer label of this {@code GarbledWire}
   */
  int getLabel() {
    return label;
  }

  /**
   * @return the signal bit. Clarification: The signal bit works as follows:
   *         When we are assigning possible values to a wire we have randomly
   *         generate a signal bit. If the signal bit is o, then the 0-encoding
   *         has a 0 as its least significant bit and the 1-encoding has a 1. If
   *         the signal bit is a 1, then the 0-encoding has a 1 as its least
   *         significant bit and the 1 encoding has a 0. What we are returning
   *         here is the last bit on the Wire which we also call the signal
   *         bit.We are not returning the initial signal bit that determined
   *         which bit to put on each wire as this information cannot be
   *         recovered(if it could be we would be able to determine the actual
   *         value of a garbled wire and thus it would not be garbled.)
   *         <p>
   *         See <i>Fairplay — A Secure Two-Party Computation System</i> by
   *         Dahlia Malkhi, Noam Nisan, Benny Pinkas, and Yaron Sella. Section
   *         4.2 describes in more detail how the signal bit works.
   *         </p>
   */
  public int getSignalBit() {
    int signalBit = (valueAndSignalBit.getEncoded()[valueAndSignalBit
        .getEncoded().length - 1] & 1) == 0 ? 0 : 1;
    return signalBit;
  }

}
