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
package edu.biu.scapi.circuits.circuit;

/**
 * The {@code Wire} class is a software representation of a {@code Wire} in a
 * circuit. As these are {@code Wire}s for Boolean circuit's each {@code Wire}
 * can be set to either 0 or 1.
 * 
 * @author Steven Goldfeder
 * 
 */
public class Wire {

  /**
   * The value that this wire carries. It can be set to either 0 or 1
   */
  private int value;

  /**
   * creates a {@code Wire} and sets it to the specified value
   * 
   * @param value
   *          the value to set this {@code Wire} to
   */
  public Wire(int value) {
    setValue(value);
  }

  /**
   * 
   * @param value
   *          the value to set this {@code Wire} to. Must be either 0 or 1.
   */
  void setValue(int value) {
    // ensures that the Wire is only set to a legal value (i.e. 0 or 1)
    if (value < 0 || value > 1) {
      throw new IllegalArgumentException("Wire value can only be 0 or 1");
    } else {
      this.value = value;
    }
  }

  /**
   * 
   * @return the value (0 or 1) that this {@code Wire} is set to
   */
  int getValue() {
    return value;
  }
}
