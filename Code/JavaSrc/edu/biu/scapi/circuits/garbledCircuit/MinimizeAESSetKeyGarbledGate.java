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

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.util.BitSet;
import java.util.Map;


import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.circuit.Gate;
import edu.biu.scapi.midLayer.ciphertext.ByteArraySymCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.primitives.prf.PseudorandomFunction;
import edu.biu.scapi.circuits.encryption.CiphertextTooLongException;
import edu.biu.scapi.circuits.encryption.KeyNotSetException;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.circuits.encryption.PlaintextTooLongException;
import edu.biu.scapi.circuits.encryption.TweakNotSetException;

/**
 * {@link MinimizeAESSetKeyGarbledBooleanCircuit} takes on the role of both a
 * garbled gate and an {@code AES128MultiKeyEncryption} in order to encypt the
 * Gate while minimizing the number of AES setKey operations. See
 * {@code MinimizeAESSetKeyGarbledBooleanCircuit} for a full discussion of the
 * reason for doing this as well as our design decisions.
 *  <p> Note that currently only the constructor and not the verify method minimizes AES set key calls
 *
 * @author Steven Goldfeder
 * 
 */
public class MinimizeAESSetKeyGarbledGate extends AbstractGarbledGate {


  private ByteArraySymCiphertext[] truthTable;

  private MultiKeyEncryptionScheme mes;
  PseudorandomFunction aes;

  public MinimizeAESSetKeyGarbledGate(Gate ungarbledGate,
      Map<Integer, SecretKey[]> allWireValues, Map<Integer, Integer> signalBits, MultiKeyEncryptionScheme mes, PseudorandomFunction aes)
      throws InvalidKeyException, IllegalBlockSizeException,
      KeyNotSetException, TweakNotSetException, PlaintextTooLongException {
    this.aes = aes;
    this.mes = mes;
    inputWireLabels = ungarbledGate.getInputWireLabels();
    outputWireLabels = ungarbledGate.getOutputWireLabels();
    gateNumber = ungarbledGate.getGateNumber();
    numberOfInputs = inputWireLabels.length;
    numberOfOutputs = outputWireLabels.length;
    /*
     * The number of rows truth table is 2^(number of inputs)
     */
    int numberOfRows = (int) Math.pow(2, numberOfInputs);
    truthTable = new ByteArraySymCiphertext[numberOfRows];
    /*
     * rather than encrypt right away as we do in StandardGarbledGate, here we
     * create arrays to hold the data. This way, we only encrypt once we have
     * all of the data ready, and thus we can minimize the number of times we
     * set the key for AES
     */
    byte[][] tweaksToEncrypt = new byte[numberOfRows][];
    byte[][] outputValuesToEncrypt = new byte[numberOfRows][];
    int[][] valuesToEncryptOn = new int[numberOfRows][];
    int[][] temp = new int[numberOfRows][];

    // an array where we put the output values
    byte[][] outputValues = new byte[numberOfRows][16];

    for (int rowOfTruthTable = 0; rowOfTruthTable < numberOfRows; rowOfTruthTable++) {
      temp[rowOfTruthTable] = new int[numberOfInputs];

      ByteBuffer tweak = ByteBuffer.allocate(16);
      tweak.putInt(gateNumber);
      int permutedPosition = 0;

      for (int i = 0, j = (int) Math.pow(2, numberOfInputs - 1), reverseIndex = numberOfInputs - 1; i < numberOfInputs; i++, j /= 2, reverseIndex--) {
        int input = ((rowOfTruthTable & j) == 0) ? 0 : 1;
        int signalBit = signalBits.get(inputWireLabels[i]);
        /*
         * the signal bits tell us the position on the garbled truth table for
         * the given row of an ungarbled truth table. See Fairplay — A Secure
         * Two-Party Computation System by Dahlia Malkhi, Noam Nisan1, Benny
         * Pinkas, and Yaron Sella for more on signal bits.
         */

        permutedPosition += (input ^ signalBit) * (Math.pow(2, reverseIndex));
        temp[rowOfTruthTable][i] = input;

        /*
         * We add the signalBit that is placed on the end of the wire's value
         * which is given by input XOR signalBit(i.e. the random bit for the
         * wire). Again, to clarify we use the term signal bit to mean both the
         * random but assigned to each wire as well as the bit that is
         * associated with each of the wire's 2 values. The latter value is
         * obtained by XORing the signal bit of the wire with the actual value
         * that the garbled value is encoding. So, for example if the signal bit
         * for the wire is 0. Then the 0-encoded value will have 0 XOR 0 = 0 as
         * its signal bit. The 1-encoded value will have 0 XOR 1 = 1 as its
         * signal bit.
         */
        tweak.putInt(input ^ signalBit);
      }
      valuesToEncryptOn[permutedPosition] = temp[rowOfTruthTable];
      tweaksToEncrypt[permutedPosition] = tweak.array();
      int value = (ungarbledGate.getTruthTable().get(rowOfTruthTable) == true) ? 1
          : 0;
      outputValuesToEncrypt[permutedPosition] = allWireValues
          .get(outputWireLabels[0])[value].getEncoded();
      // tweak - what is to be encrypted
      // value--which output wire to xor the encrypted tweak to--0 or 1
      // permuted position- where to put the result in the output array

    }
    /*
     * we now encrypt the tweaks on the necessary value. We set AES to each
     * value and then look for all rows that need to be encrypted on this value
     * before we reset the key.
     */
    for (int i = 0; i < numberOfInputs; i++) {
      aes.setKey(allWireValues.get(inputWireLabels[i])[0]);
      for (int rowNumber = 0; rowNumber < numberOfRows; rowNumber++) {
        if (valuesToEncryptOn[rowNumber][i] == 0) {
          byte[] tempo = new byte[16];
          aes.computeBlock(tweaksToEncrypt[rowNumber], 0, tempo, 0);
          for (int byteNumber = 0; byteNumber < tempo.length; byteNumber++) {

            outputValues[rowNumber][byteNumber] ^= tempo[byteNumber];
          }
        }

      }

      aes.setKey(allWireValues.get(inputWireLabels[i])[1]);
      for (int rowNumber = 0; rowNumber < numberOfRows; rowNumber++) {
        if (valuesToEncryptOn[rowNumber][i] == 1) {
          byte[] tempo = new byte[16];
          aes.computeBlock(tweaksToEncrypt[rowNumber], 0, tempo, 0);
          for (int byteNumber = 0; byteNumber < tempo.length; byteNumber++) {
            outputValues[rowNumber][byteNumber] ^= tempo[byteNumber];
          }
        }
      }
    }
    /*
     * now that we encrypted the tweaks and XOR them to each other, we XOR the
     * result to outputValue, the plaintext
     */
    for (int rowNumber = 0; rowNumber < numberOfRows; rowNumber++) {
      for (int byteNumber = 0; byteNumber < 16; byteNumber++)
        outputValues[rowNumber][byteNumber] ^= outputValuesToEncrypt[rowNumber][byteNumber];
    }
    /*
     * Finally we assign the encrypted results to the correspinding row of the
     * garbled truth table
     */
    for (int rowNumber = 0; rowNumber < numberOfRows; rowNumber++) {
      truthTable[rowNumber] = new ByteArraySymCiphertext(
          outputValues[rowNumber]);
    }
  }

  public void compute(Map<Integer, GarbledWire> computedWires)
      throws InvalidKeyException, IllegalBlockSizeException,
      CiphertextTooLongException, KeyNotSetException, TweakNotSetException {
    int truthTableIndex = getIndexToDecrypt(computedWires);
    /*
     * we regenerate the multiSecretKEy and the tweak. We then reset the tweak
     * and the key to the MultiKeyEncryptionScheme and call its decrypt function
     */
    SecretKey[] keysToDecryptOn = new SecretKey[numberOfInputs];
    for (int i = 0; i < numberOfInputs; i++) {
      keysToDecryptOn[i] = computedWires.get(inputWireLabels[i])
          .getValueAndSignalBit();
    }
    mes.setKey(mes.generateMultiKey(keysToDecryptOn));
    ByteBuffer tweak = ByteBuffer.allocate(16);
    // first we put the gate number in the tweak
    tweak.putInt(gateNumber);
    // next we put the signal bits of the input wire values into the tweak
    for (int i = 0; i < numberOfInputs; i++) {
      tweak.putInt(computedWires.get(inputWireLabels[i]).getSignalBit());
    }
    mes.setTweak(tweak.array());

    SecretKey wireValue = new SecretKeySpec(
        ((ByteArrayPlaintext) mes.decrypt(truthTable[truthTableIndex]))
            .getText(),
        "");

    for (int i = 0; i < numberOfOutputs; i++) {

      computedWires.put(outputWireLabels[i], new GarbledWire(
          outputWireLabels[i], wireValue));

    }
  }

  /**A helper method that computed which index to decrypt based on the signal bits of the input wires.
   * @param computedWires a {@code Map} containing the input wires and their values. We will use it to obtain the 
   * signal bits of the values of the input wires in order to determine the correct index to decrypt
   * @return the index of the garbled truth table that the input wires' signal bits signal to decrypt
   */
  private int getIndexToDecrypt(Map<Integer, GarbledWire> computedWires) {
    int truthTableIndex = 0;
    for (int i = numberOfInputs - 1, j = 0; j < numberOfInputs; i--, j++) {
      truthTableIndex += computedWires.get(inputWireLabels[i]).getSignalBit()
          * Math.pow(2, j);
    }
    return truthTableIndex;
  }

  @Override
  public boolean verify(Gate g, Map<Integer, SecretKey[]> allWireValues)
      throws IllegalBlockSizeException, CiphertextTooLongException,
      KeyNotSetException, TweakNotSetException, InvalidKeyException {

    /*
     * Step 1: First we test to see that these gate's are labeled with the same
     * integer label. if they're not, then for our purposes they are not
     * identical. The reason that we treat this as unequal is since in a larger
     * circuit corresponding gates must be identically labeled in order for the
     * circuits to be the same.
     */
    if (gateNumber != g.getGateNumber()) {
      return false;
    }
    /*
     * Step 2: we check to ensure that the inputWirelabels and ouputWireLabels
     * are the same
     */
    int[] ungarbledInputWireLabels = g.getInputWireLabels();
    int[] ungarbledOutputWireLabels = g.getOutputWireLabels();

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
     * Step 3. Use allWireValues(i.e. a map that maps each wire to an array that
     * contains its 0-encoding and its 1-encoding) to go through every
     * combination of input wire values and decrypt the corresponding row of the
     * truth table
     * 
     * Step 4. The decrypted values of the truth table should be(at most) 2
     * distinct keys--i.e. a 0-encoding for the output wire and a 1-encoding for
     * the output wire. So, we test whether the arrangement of the garbled truth
     * table is consistent with the ungarbled truth table. Specifically, if the
     * ungarbled truth table is 0001, then we test to ensure that the first,
     * second and third entries of the garbled truth table are identical and
     * that the fourth entry is different. If this is not true, we return false
     * as the two truth tables are not consistent. If this is true, then we add
     * the output wires with the corresponding values to the allWireValues map.
     * Thus, in our example with the 0001 truth table, the garbled value that
     * corresponds to 0(i.e it appears in the first, second and third positions
     * of the truth table) is stored as the 0 value for the output wire. The
     * value corresponding to 1 is stored as the 1 value for the output wire.
     */

    BitSet ungarbledTruthTable = g.getTruthTable();
    SecretKey outputZeroValue = null;
    SecretKey outputOneValue = null;
    // The outer for loop goes through each row of the truth table
    for (int rowOfTruthTable = 0; rowOfTruthTable < Math.pow(2, numberOfInputs); rowOfTruthTable++) {

      /*
       * permuted position will be the index of the garbled truth table
       * corresponding to rowOfTruthTable
       */
      int permutedPosition = 0;
      ByteBuffer tweak = ByteBuffer.allocate(16);
      tweak.putInt(gateNumber);
      SecretKey[] keysToDecryptOn = new SecretKey[numberOfInputs];
      /*
       * This for loop goes through from left to right the input of the given
       * row of the truth table.
       */
      for (int i = 0, j = (int) Math.pow(2, numberOfInputs - 1), reverseIndex = numberOfInputs - 1; i < numberOfInputs; i++, j /= 2, reverseIndex--) {
        int input = ((rowOfTruthTable & j) == 0) ? 0 : 1;
        SecretKey currentWireValue = allWireValues.get(inputWireLabels[i])[input];
        /*
         * add the current Wire value to the list of keys to decrypt on. These
         * keys will then be used to construct a multikey.
         */
        keysToDecryptOn[i] = currentWireValue;
        /*
         * look up the signal bit on this wire. This is the last bit of its
         * value.
         */
        int signalBit = (currentWireValue.getEncoded()[currentWireValue
            .getEncoded().length - 1] & 1) == 0 ? 0 : 1;
        /*
         * update the permuted position. After this loop finishes, permuted
         * position will be the position on the garbled truth table for this
         * input wire combination. For a better understanding on how this works,
         * see the getIndexToDecrypt method in this class
         */
        permutedPosition += signalBit * Math.pow(2, reverseIndex);
        // add the signal bit of this input wire value to the tweak
        tweak.putInt(signalBit);
      }
      mes.setKey(mes.generateMultiKey(keysToDecryptOn));
      mes.setTweak(tweak.array());
      ByteArrayPlaintext pt = mes.decrypt(truthTable[permutedPosition]);
      /*
       * we now check to see that rows of the truth table with the same
       * ungarbled value have the same garbled value as well
       */
      if (ungarbledTruthTable.get(rowOfTruthTable) == true) {// i.e this bit is
                                                             // set
        if (outputOneValue != null) {
          byte[] ptBytes = pt.getText();
          byte[] oneValueBytes = outputOneValue.getEncoded();
          for (int byteArrayIndex = 0; byteArrayIndex < ptBytes.length; byteArrayIndex++) {
            if (ptBytes[byteArrayIndex] != oneValueBytes[byteArrayIndex]) {
              return false;
            }
          }
        } else {
          outputOneValue = new SecretKeySpec(pt.getText(), "");
        }
      } else { // i.e if(ungarbledTruthTable.get(rowOfTruthTable)==false)
                                                        //bit is not set
        if (outputZeroValue == null) {
          outputZeroValue = new SecretKeySpec(pt.getText(), "");
        } else {
          byte[] ptBytes = pt.getText();
          byte[] zeroValueBytes = outputZeroValue.getEncoded();
          for (int byteArrayIndex = 0; byteArrayIndex < ptBytes.length; byteArrayIndex++) {
            if (ptBytes[byteArrayIndex] != zeroValueBytes[byteArrayIndex]) {
              return false;
            }
          }
        }
      }
    }
    //we add the output wire to the allWireValues Map
    for (int w : outputWireLabels) {
      allWireValues.put(w, new SecretKey[] {outputZeroValue, outputOneValue });
    }
    return true;
  }
}
