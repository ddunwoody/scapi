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


import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;


/**
 * 
 * This is the code for the Sender side of the protocol Semi-Honest batch OT assuming DDH. The protocol is a Two-round oblivious transfer 
 * based on the DDH assumption that achieves security in the presence of semi-honest adversaries. The pseudocode can be found in
 * SCAPI pseudocode specifications protocl 7.1, reference OT_DDH_SEMIHONEST_BATCH. We use a batch version for multiple values.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University ( Meital Levy)
 *
 */
public class BatchOtDdhSemiHonestSender implements Protocol{

	private DlogGroup dlog = null;//from pseudocode: Common input: (G,q,g) where (G,q,g) is a DLOG description
	private KeyDerivationFunction kdf = null; //used for adjusting the elements into byte[] of the needed size
	private int numberOfOutputDataElements;
	private BigInteger randomValue; //stores a random value sampled
	private ArrayList<GroupElementSendableData> uVector;  //stores u for each index
	private ArrayList<GroupElementSendableData> k1Vector; //stores k0 for each index
	private ArrayList<GroupElementSendableData> k0Vector; //stores k1 for each index
	private ArrayList<byte[]> v0Vector;//stores v0 for each index
	private ArrayList<byte[]> v1Vector;//stores v1 for each index
	private LinkedList<ArrayList<GroupElementSendableData>> listOf2Vectors = null;//a list of 2 vectors of data that we receive from the receiver
	private LinkedList<ArrayList> listToSend = null;
	private Map<Integer, SecretKey[]> allInputs = null; //a map with both keys of input. This is x0 and x1 for every index
	protected ArrayList<Integer> recieverInputWireLabels; //the labels for party 2
	private Channel channel; //the channel 
	
	
	/**
	 * 
	 * @param channel the channel for communicating with the receiver. Used for sending and receiving data
	 * @param numberOfOutputDataElements the number of 
	 * @param allInputs x0 and x1 for every index
	 * @param recieverInputWireLabels the labels needed by the receiver.
	 * @param dlog the dlog group, this is part of the common input. From pseudocode: Common input: (G,q,g) where (G,q,g) is a DLOG description
	 * @param kdf used for adjusting the elements into byte[] of the needed size
	 */
	public BatchOtDdhSemiHonestSender(Channel channel, int numberOfOutputDataElements, Map<Integer, SecretKey[]> allInputs, List<Integer> recieverInputWireLabels,  DlogGroup dlog, KeyDerivationFunction kdf) {
		
		this.channel = channel;
		this.dlog = dlog;
		this.kdf = kdf;
		this.numberOfOutputDataElements = numberOfOutputDataElements;
		this.allInputs = allInputs;
		this.recieverInputWireLabels = (ArrayList<Integer>) recieverInputWireLabels;
		uVector = new ArrayList<GroupElementSendableData>();//we only need a single value
		k1Vector = new ArrayList<GroupElementSendableData>(numberOfOutputDataElements);//numberOfOutputDataElements);
		k0Vector = new ArrayList<GroupElementSendableData>(numberOfOutputDataElements);//numberOfOutputDataElements);
		v0Vector = new ArrayList<byte[]>(numberOfOutputDataElements);
		v1Vector = new ArrayList<byte[]>(numberOfOutputDataElements);
		listToSend = new LinkedList();
		
		
		
	}
	/**
	 * runs the sender side of the protocol.
	 * 
	 * In general the sender side does the following
	 * 
	 * 1. Samples a random value 
	 * 2. recieves values from the reciever 
	 * 3. computes values taking into account the values recieved and send the computed values 
	 * 
	 */
	public void run() {
		
		
		//calc u=g^r before waiting for message from the receiver since these values are independent
		sampleRandomValuesAndSetHValuesBeforeReceivingData();
		
		//pseudocode : WAIT for message (h0,h1) from R
		receiveHVectors();
		
		//compute the values needed considering the values received
		computeValuesToSend();
		
		//send the final message of the computed values
		sendComputedValues();
		
			
		
	}

	/**
	 * Adds u,v0,vi to the list and send it as a single message to the receiver
	 */
	private void sendComputedValues(){
		//add u,v9,v1 to the list to send the reciever
		listToSend.add(uVector);
		listToSend.add(v0Vector);
		listToSend.add(v1Vector);
		
		try {
			channel.send(listToSend);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * sample a random value r and compute all needed values to send to the reciever. Then, send these computed values to the reciever
	 * 
	 * From pseudocode : For each value do 
	 * 
	 * SAMPLE a random value r in {0, . . . , q-1} //only need to sample a single r for all calculations
	 * COMPUTE:
	 * u = g^r //do once
	 * k0 = h0^r
	 * v0 = x0 XOR KDF(|x0|,k0)
	 * k1 = h1^r
	 * v1 = x1 XOR KDF(|x1|,k1)
	 */
	private void computeValuesToSend() {
		//get the h vectors from the list
		ArrayList<GroupElementSendableData> h0Vector = listOf2Vectors.get(0);
		ArrayList<GroupElementSendableData> h1Vector = listOf2Vectors.get(1);
		for(int i=0;i<numberOfOutputDataElements; i++){
			
			//set all the K0 values
			k0Vector.add(dlog.exponentiate(dlog.generateElement(false, h0Vector.get(i)), randomValue).generateSendableData());
			
			//set all the K1 values
			k1Vector.add(dlog.exponentiate(dlog.generateElement(false, h1Vector.get(i)), randomValue).generateSendableData());
			
			//element to byte array
			byte[] groupElementBytes0 = dlog.mapAnyGroupElementToByteArray(dlog.generateElement(false,k0Vector.get(i)));
			byte[] groupElementBytes1 = dlog.mapAnyGroupElementToByteArray(dlog.generateElement(false,k1Vector.get(i)));
			
			
			//set all V0 and V1 values. In pseudocode : v0 = x0 XOR KDF(|x0|,k0)
			//make sure to take the relevant key from the corresponding garbled wire label
			
			byte[] x0 = allInputs.get(recieverInputWireLabels.get(i))[0].getEncoded();
			byte[] x1 = allInputs.get(recieverInputWireLabels.get(i))[1].getEncoded();
			
			//KDF(|x0|,k0)
			byte[] rightHandEquation0 = (kdf.derivateKey(groupElementBytes0, 0, groupElementBytes0.length, x0.length)).getEncoded();
			//KDF(|x1|,k1)
			byte[] rightHandEquation1 = (kdf.derivateKey(groupElementBytes1, 0, groupElementBytes1.length, x1.length)).getEncoded();
			
			
			byte[] result0 = new byte[rightHandEquation0.length];
			byte[] result1 = new byte[rightHandEquation1.length];
			
			//Xor each byte
			for (int j = 0; j < rightHandEquation1.length; j++)
	        {
				result0[j] = (byte) (rightHandEquation0[j] ^ x0[j]);
				result1[j] = (byte) (rightHandEquation1[j] ^ x1[j]);
	        }
			
			v0Vector.add(result0 );
			v1Vector.add(result1 );
			
		}
	}

	/**
	 * Receives the h0 and h1 values
	 */
	private void receiveHVectors() {
		//make a list of the h vectors in order to get the message fro message from the reciever
		listOf2Vectors = new LinkedList<ArrayList<GroupElementSendableData>>();
	
		
		//get the 2 vectors of the receiver. From pseudocode of the sender: "SEND (h0,h1) to S"
		try {
			listOf2Vectors = (LinkedList<ArrayList<GroupElementSendableData>>) channel.receive();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	/**
	 * sample a random value and set h=g^r. Sample a single value for all the indices 
	 * This can be done independently before receiving any data.
	 * 
	 */
	private void sampleRandomValuesAndSetHValuesBeforeReceivingData() {
		BigInteger one = BigInteger.ONE;
		BigInteger qMinusOne = dlog.getOrder().subtract(one);
		
		//get the group generator
		GroupElement generator = dlog.getGenerator();
					
		// choose a random number r in Zq*
		randomValue= BigIntegers.createRandomInRange(one, qMinusOne, new SecureRandom());
		
		//set the g^r value 
		uVector.add(dlog.exponentiate(generator, randomValue).generateSendableData());
		
	}
	@Override
	public ProtocolOutput getOutput() {
		// TODO Auto-generated method stub
		return null;
	}
}
