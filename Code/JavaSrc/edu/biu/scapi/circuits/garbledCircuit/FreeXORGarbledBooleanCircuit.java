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
import java.util.BitSet;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.Gate;
import edu.biu.scapi.circuits.encryption.KeyNotSetException;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.circuits.encryption.PlaintextTooLongException;
import edu.biu.scapi.circuits.encryption.TweakNotSetException;

/**
 * The {@code FreeXORGarbledBooleanCircuit} uses the Free XOR technique that is
 * explained in depth in <i>Free XOR Gates and Applications</i> by Validimir
 * Kolesnikov and Thomas Schneider. This circuit's computes method chooses the
 * wire labels according to the procedure delineated in the above described
 * paper. It then replaces all XOR gates with {@code FreeXOR gates} and these
 * gates can be computed without encryption due to the way the wire's values
 * were chosen. See the above paper also for a proof of security of this method.
 * <p>
 * Note also that the {@link #compute()} method of
 * {@code FreeXORGarbledBooleanCircuit} is no different than the standard
 * {@code StandardGarbledBooleanCircuit}. The reason for this is that we
 * designed the circuit so that the circuit's compute method just calls the
 * gate's verify method. In the compute method, we use the interface
 * {@link GarbledGate} to make our calls and thus the appropriate verify method
 * for the dynamic type of the specified gate is automatically waht is used. For
 * the saem reason, the {@link #verify(BooleanCircuit, Map)} method of
 * {@code FreeXORGarbledBooleanCircuit} is also identical to
 * {@code StandardGarbledBooleanCircuit}'s verify method.
 * </p>
 * 
 * @author Steven Goldfeder
 * 
 */
public class FreeXORGarbledBooleanCircuit extends AbstractGarbledBooleanCircuit {

	/**
	 * @param ungarbledCircuit
	 *          the circuit that we will garble
	 * @param mes
	 *          The MultiKeyEncryptionScheme that will be used to garble and
	 *          compute this circuit.
	 * @param allInputWireValues
	 *          a map that is passed as a parameter. It should be blank when
	 *          passed as a parameter and the constructor will add to it the 0 and
	 *          1 SecretKey values for each input Wire. The reason that this is
	 *          passed as a parameter and not created here or stored as a field is
	 *          because we need the constructing and only the constructing
	 *          party(from hereon in Alice) to have access to this. The second
	 *          party--i.e. the one that will compute on the circuit(from hereon
	 *          in Bob) should not know which input wire value is 0 and which is 1
	 *          nor should Bob have access to both the 0 and 1 values. Rather, Bob
	 *          is given access to only a single value for each input wire, and he
	 *          does not know what this value encodes. Alice gives Bob the
	 *          appropriate garbled values for her inputs, and Bob gets the value
	 *          for his input from Alice via oblivious transfer. Thus, we have
	 *          designed this class so that only Alice will have access to the map
	 *          with both values of each input wire.
	 *          <p>
	 *          Note that there is one case in which Alice will give this map to
	 *          Bob: In the case of a malicious adversary, Alice will construct
	 *          multiple circuits and Bob will ask Alice to uncover some of them
	 *          to verify them(using our verify method. The way that Alice
	 *          uncovers these is by giving Bob access to the allInputWireValues
	 *          map. Bob calls the verify method and passes this map as well as
	 *          the agreed upon(ungarbled) circuit to the verify method to test
	 *          that Alice constructed the circuit correctly.
	 *          </p>
	 *          <p>
	 *          See <i>Secure Multiparty Computation for Privacy-Preserving Data
	 *          Mining</i> by Yehuda Lindell and Benny Pinkas Section 3 for an
	 *          overview of Yao's protocol, and a more in depth explanation of all
	 *          that is discussed here.
	 *          </p>
	 * @throws PlaintextTooLongException
	 * @throws TweakNotSetException
	 * @throws KeyNotSetException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidKeyException
	 */
	public FreeXORGarbledBooleanCircuit(BooleanCircuit ungarbledCircuit,
			MultiKeyEncryptionScheme mes, Map<Integer, SecretKey[]> allInputWireValues)
					throws InvalidKeyException, IllegalBlockSizeException,
					KeyNotSetException, TweakNotSetException, PlaintextTooLongException {

		this.mes = mes;
		translationTable = new HashMap<Integer, Integer>();
		outputWireLabels = ungarbledCircuit.getOutputWireLabels();
		inputWireLabels = ungarbledCircuit.getInputWireLabels();
		Gate[] ungarbledGates = ungarbledCircuit.getGates();
		numberOfWires = ungarbledCircuit.getNumberOfWires();
		gates = new GarbledGate[ungarbledGates.length];
		Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
		Map<Integer, Integer> signalBits = new HashMap<Integer, Integer>();
		/*
		 * The globalKeyOffset is a randomly chosen bit sequence that is the same
		 * size as the key and will be used to create the garbled wire's values
		 * 
		 * We used generate key since this way globalKeyOfset will always be the size
		 * of the key plus permutation bit. See Free XOR Gates and Applications by
		 * Validimir Kolesnikov and Thomas Schneider
		 */
		byte[] globalKeyOffset = mes.generateKey().getEncoded();
		/*
		 * setting the last bit to 1. This follows algorithm 1 step 2 part A of Free
		 * XOR Gates and Applications by Validimir Kolesnikov and Thomas Schneider.
		 * This algorithm calls for XORing the Wire values with R and the signal bit
		 * with 1. So, we set the last bit of R to 1 and this will be XOR'd with the
		 * last bit of the wire value, which is the signal bit in our
		 * implementation.
		 */
		globalKeyOffset[globalKeyOffset.length - 1] |= 1;
		//
		for (int w : inputWireLabels) {
			SecretKey zeroValue = mes.generateKey();
			SecretKey oneValue;
			byte[] zeroValueBytes = zeroValue.getEncoded();
			int signalBit = (zeroValueBytes[zeroValueBytes.length - 1] & 1) == 0 ? 0
					: 1;
			signalBits.put(w, signalBit);
			byte[] oneValueBytes = new byte[zeroValueBytes.length];
			for (int i = 0; i < zeroValueBytes.length; i++) {
				oneValueBytes[i] = (byte) (zeroValueBytes[i] ^ globalKeyOffset[i]);
			}
			oneValue = new SecretKeySpec(oneValueBytes, "");
			allWireValues.put(w, new SecretKey[] { zeroValue, oneValue });
		}
		// create the XOR truth table to be used to test against for equality
		BitSet XORTruthTable = new BitSet();

		XORTruthTable = new BitSet();
		XORTruthTable.set(1);
		XORTruthTable.set(2);

		for (int gate = 0; gate < ungarbledGates.length; gate++) {
			SecretKey zeroValue;
			SecretKey oneValue;
			if (ungarbledGates[gate].getTruthTable().equals(XORTruthTable)) {
				byte[] zeroValueBytes = allWireValues.get(ungarbledGates[gate]
						.getInputWireLabels()[0])[0].getEncoded();// bytes of first input
				for (int i = 1; i < ungarbledGates[gate].getInputWireLabels().length; i++) {
					byte[] nextInput = allWireValues.get(ungarbledGates[gate]
							.getInputWireLabels()[i])[0].getEncoded();
					for (int currentByte = 0; currentByte < zeroValueBytes.length; currentByte++) {
						zeroValueBytes[currentByte] ^= nextInput[currentByte];
					}
				}
				byte[] oneValueBytes = new byte[zeroValueBytes.length];
				for (int i = 0; i < zeroValueBytes.length; i++) {
					oneValueBytes[i] = (byte) (zeroValueBytes[i] ^ globalKeyOffset[i]);
				}
				int signalBit = (zeroValueBytes[zeroValueBytes.length - 1] & 1) == 0 ? 0
						: 1;
				signalBits
				.put(ungarbledGates[gate].getOutputWireLabels()[0], signalBit);
				zeroValue = new SecretKeySpec(zeroValueBytes, "");
				oneValue = new SecretKeySpec(oneValueBytes, "");

				allWireValues.put(ungarbledGates[gate].getOutputWireLabels()[0],
						new SecretKey[] { zeroValue, oneValue });

				gates[gate] = new FreeXORGate(ungarbledGates[gate]);
				//for non XOR gates
			} else {
				zeroValue = mes.generateKey();
				byte[] zeroValueBytes = zeroValue.getEncoded();
				byte[] oneValueBytes = new byte[zeroValueBytes.length];
				int signalBit = (zeroValueBytes[zeroValueBytes.length - 1] & 1) == 0 ? 0
						: 1;
				signalBits
				.put(ungarbledGates[gate].getOutputWireLabels()[0], signalBit);
				for (int i = 0; i < zeroValueBytes.length; i++) {
					oneValueBytes[i] = (byte) (zeroValueBytes[i] ^ globalKeyOffset[i]);
				}

				zeroValue = new SecretKeySpec(zeroValueBytes, "");
				oneValue = new SecretKeySpec(oneValueBytes, "");

				allWireValues.put(ungarbledGates[gate].getOutputWireLabels()[0],
						new SecretKey[] { zeroValue, oneValue });
				gates[gate] = new StandardGarbledGate(mes, ungarbledGates[gate],
						allWireValues, signalBits);
			}

		}

		for (int n : outputWireLabels) {
			translationTable.put(n, signalBits.get(n));

		}
		/*
		 * add both values of input wire labels to the addInputWireLabels Map that
		 * was passed as a parameter
		 */
		for (int w : inputWireLabels) {
			allInputWireValues.put(w, allWireValues.get(w));
		}
	}
}
