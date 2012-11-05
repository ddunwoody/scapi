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

import java.util.BitSet;

/**
 * 
 * A built in NOT Gate for the convenience of circuit designers. This gate is
 * identical to creating a Gate with a 0001 truth table.
 * 
 * @author Steven Goldfeder
 * 
 */

public class NOTGate extends Gate {
  /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

/**
   * Constructs a NOT Gate
   * 
   * @param gateNumber
   *          the gate's integer label(in a circuit all gates will be labeled)
   * @param inputWireLabel
   *          an array containing the labels of the gate's input {@code Wire}.
   *          Since NOT is a unary operator, there will only be one input
   *          {@code Wire.}
   * @param outputWireLabels
   *          an array containing the labels of the gate's input {@code Wire}
   *          (s). There will generally be a single output {@code Wire}. However
   *          in instances in which fan-out of the output {@code Wire} is >1, we
   *          left the option for treating this as multiple {@code Wire}s
   */

  NOTGate(int gateNumber, int inputWireLabel, int[] outputWireLabels) {
    super(gateNumber, createNOTTruthTable(), new int[] { inputWireLabel },
        outputWireLabels);
  }

  /**
   * 
   * @return a BitSet representation of a NOT Gate truth table to be passed to
   *         the super constructor
   */
  private static BitSet createNOTTruthTable() {
    BitSet truthTable = new BitSet();
    truthTable.set(0);
    return truthTable;
  }

}
