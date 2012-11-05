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

import java.util.BitSet;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.circuit.Gate;

/**
 * See <i>Free XOR Gates and Applications</i> by Validimir Kolesnikov and Thomas
 * Schneider for a full description of the Free XOR technique, pseudocode
 * implementation, as well as the proof of security. As they mention in that
 * paper, a Free XOR gate with n > 2 inputs can be broken down into n-1 2-input
 * XOR gates. Hence, we implement the Free XOR optimization for 2-input XOR
 * Gates, and we leave it to the circuit designer to maximize the number of
 * 2-input XOR gates.
 * <p>
 * The Free XOR optimization allows XOR Gates to be evaluated for free--i.e.
 * without encryption, and thus significantly speeds up Garbled Circuit
 * computations on large circuits with many XOR Gates. The technique dictates a
 * careful way to choose the Wire Values. See the
 * {@link FreeXORGarbledCBooleanCircuit} class where we construct the circuit
 * and choose the values according to this procedure. Once the Wwire values have
 * been chosen as such, evaluating XOR gates does not require encryption. See
 * the {@link #compute(Map)} method in this class where the computation is done.
 * </p>
 * 
 * 
 * @author Steven Goldfeder
 * 
 */
public class FreeXORGate extends AbstractGarbledGate{

    

  /**
   * @param ungarbledGate
   *          The ungarbled Gate that is to be Garbled. Since this is an XOR
   *          Gate using the Free XOR technique, no encryption is required for
   *          its Garbling. Rather, the {@code GarbledWire} values were
   *          carefully chosen in the @ code GarbledBooleanCiircuit} . See
   *          {@code StandardGarbledBooleanCircuit} and {@link #compute(Map)} for the
   *          technical details on how this is achieved.
   */
  public FreeXORGate(Gate ungarbledGate) {
    inputWireLabels = ungarbledGate.getInputWireLabels();
    outputWireLabels = ungarbledGate.getOutputWireLabels();
    numberOfInputs = inputWireLabels.length;
    numberOfOutputs = outputWireLabels.length;
    gateNumber = ungarbledGate.getGateNumber();

  }

  @Override
  public void compute(Map<Integer, GarbledWire> computedWires) {
    byte[] outputValue = computedWires.get(inputWireLabels[0])
        .getValueAndSignalBit().getEncoded();
    /*
     * The Free XOR Gate has only 2 inputs. We XOR the input values to obtain
     * the Garbled output value. This is made possible by carefully choosing the
     * garbled values for the {@code Garbled Wires} in the constructor of the
     * {@code FreeXORGarbledBooleanCircuit} class. See there for details.
     */
    byte[] nextInput = computedWires.get(inputWireLabels[1])
        .getValueAndSignalBit().getEncoded();

    // XORing the two input values
    for (int currentByte = 0; currentByte < outputValue.length; currentByte++) {
      outputValue[currentByte] ^= nextInput[currentByte];
    }

    SecretKey outputWireValue = new SecretKeySpec(outputValue, "");
    // We now create the output GarbledWire(s) and set them with the value we
    // just computed
    for (int w : outputWireLabels) {
      computedWires.put(w, new GarbledWire(w, outputWireValue));
    }

  }

  @Override
  public boolean verify(Gate g, Map<Integer, SecretKey[]> allWireValues) {
    /*
     * Step 1: First we test to see that these gates are labeled with the same
     * integer label. if they're not, then for our purposes they are not
     * identical. The reason that we treat this as unequal is since in a larger
     * circuit corresponding gates must be identically labeled in order for the
     * circuits to be the same.
     */
    if (gateNumber != g.getGateNumber()) {
      return false;
    }
    /*
     * Next we check to ensure that the two gates have the same respective
     * numbers of input and output wires and that the inputWirelabels and
     * ouputWireLabels are the same
     */
    int[] ungarbledInputWireLabels = g.getInputWireLabels();
    int[] ungarbledOutputWireLabels = g.getOutputWireLabels();
    // the numbe of inputs should always be 2 since this is a 20input free XOR
    // gate, but nevertheless we test it
    if (numberOfInputs != ungarbledInputWireLabels.length
        || numberOfOutputs != ungarbledOutputWireLabels.length) {
      return false;
    }
    for (int i = 0; i < numberOfInputs; i++) {
      if (inputWireLabels[i] != ungarbledInputWireLabels[i]) {
        return false;
      }
    }
    for (int i = 0; i < numberOfOutputs; i++) {
      if (outputWireLabels[i] != ungarbledOutputWireLabels[i]) {
        return false;
      }
    }

    /*
     * Since this is a Free XOR Gate, we know that the ungarbled Gate must be an
     * XOR Gate if they are equivalent. So, we check to see that the truth table
     * is 0110
     */
    BitSet ungarbledTruthTable = g.getTruthTable();
    if (ungarbledTruthTable.get(0) != false
        || ungarbledTruthTable.get(1) != true
        || ungarbledTruthTable.get(2) != true
        || ungarbledTruthTable.get(3) != false) {
      return false;
    }
    /*
     * The last step that we must do is add the values for the output wire(s) to
     * the allWireValues map. This is necessary since the
     * FreeXORGarbledBooleanCircuit's verify method that calls this method needs
     * this map updated since subsequent Gates may have this gate's output Wire
     * as an input Wire and need the values to verify equality.(Non
     * FreeXORGate's need both Wire values to verify the that the truth table's
     * are equal)
     */

    /*
     * first we get the 0 output value by using the 0-0 values as inputs and
     * XORing them to get the 0-encoded output I call it zeroZero since its the
     * zero value of the 0th GarbledWire in the input array
     */
    byte[] zeroZero = allWireValues.get(inputWireLabels[0])[0].getEncoded();
    /*
     * I call it oneZero since its the zero value of the 1th GarbledWire in the
     * input array
     */
    byte[] oneZero = allWireValues.get(inputWireLabels[1])[0].getEncoded();
    // We now XOR the values to obtain the result
    byte[] outputZero = new byte[zeroZero.length];
    for (int currentByte = 0; currentByte < zeroZero.length; currentByte++) {
      outputZero[currentByte] = (byte) (zeroZero[currentByte] ^ oneZero[currentByte]);
    }
    /*
     * next we get the 1 output value by using the 0-1 values as inputs oneOne
     * is the one value of the input GarbledWire with index 1 in the
     * inputwireLabels array
     */
    byte[] oneOne = allWireValues.get(inputWireLabels[1])[1].getEncoded();
    // we now XOR the 0-1 input values to get the output 1-encoded value
    byte[] outputOne = new byte[zeroZero.length];
    for (int currentByte = 0; currentByte < zeroZero.length; currentByte++) {
      outputOne[currentByte] = (byte) (zeroZero[currentByte] ^ oneOne[currentByte]);
    }
    for (int w : outputWireLabels) {
      allWireValues.put(w, new SecretKey[] { new SecretKeySpec(outputZero, ""),
          new SecretKeySpec(outputOne, "") });
    }
    return true;
  }
}
