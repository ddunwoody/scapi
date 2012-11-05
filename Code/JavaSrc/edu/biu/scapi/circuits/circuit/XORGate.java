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
 * A built in XOR Gate for the convenience of circuit designers. This gate is
 * identical to creating a Gate with a 0001 truth table.
 * 
 * @author Steven Goldfeder
 * 
 */

public class XORGate extends Gate {

  /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

/**
   * Constructs an XOR Gate
   * 
   * @param gateNumber
   *          the gate's integer label(in a circuit all {@code Gate} will be
   *          labeled)
   * @param inputWireLabels
   *          an array containing the labels of the {@code Gate}'s input
   *          {@code Wire}s
   * @param outputWireLabels
   *          an array containing the labels of the {@code Gate}'s input
   *          {@code Wire}(s). There will generally be a single output
   *          {@code Wire}. However in instances in which fan-out of the output
   *          {@code Wire} is >1, we left the option for treating this as
   *          multiple {@code Wire}s
   */

  XORGate(int gateNumber, int[] inputWireLabels, int[] outputWireLabels) {
    super(gateNumber, createXORTruthTable(), inputWireLabels, outputWireLabels);
  }

  /**
   * 
   * @return a BitSet representation of an XOR Gate truth table to be passed to
   *         the super constructor
   */

  private static BitSet createXORTruthTable() {
    BitSet truthTable = new BitSet();
    truthTable.set(1);
    truthTable.set(2);
    return truthTable;
  }

}
