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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;


/**
 * 
 * This is the code for the Receiver side of the protocol Semi-Honest batch OT assuming DDH. The protocol is a Two-round oblivious transfer 
 * based on the DDH assumption that achieves security in the presence of semi-honest adversaries. The pseudocode can be found in
 * SCAPI pseudocode specifications protocl 7.1, reference OT_DDH_SEMIHONEST_BATCH. We use a batch version for multiple values.
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University ( Meital Levy)
 *
 */
public class BatchOtDdhSemiHonestReceiver implements Protocol{

	
	private DlogGroup dlog = null;//from pseudocode: Common input: (G,q,g) where (G,q,g) is a DLOG description
	private KeyDerivationFunction kdf = null; //used for adjusting the elements into byte[] of the needed size
	private int[] inputBits=null; //the input bits of the receiver. From pseucocode : R's private input: a bit sigma in  {0, 1}
	private int numberOfInputBits; //the size of the batch OT. Meaning the number of elemets we want to receive
	private BigInteger [] randomValues=null; //stores random values sampled
	private ArrayList<GroupElementSendableData> h0Vector=null; //stores h0 for each index
	private ArrayList<GroupElementSendableData> h1Vector=null; //stores h1 for each index
	private ArrayList<SecretKey> result = null; //the final result received by the receiver. 
	
	private LinkedList<ArrayList> listOfRecievedValues = null;//a list that stores the 3 values received from the sender
	private Channel channel;//the channel with the other party. Used for sending and receiving data
	
	
	/**
	 * 
	 * @param channel the channel with the other party. Used for sending and receiving data
	 * @param dlog the dlog group, this is part of the common input. From pseudocode: Common input: (G,q,g) where (G,q,g) is a DLOG description
	 * @param kdf used for adjusting the elements into byte[] of the needed size
	 * @param inputBits the input bits of the receiver. From pseucocode : R's private input: a bit sigma in  {0, 1}
	 */
	public BatchOtDdhSemiHonestReceiver(Channel channel, DlogGroup dlog, KeyDerivationFunction kdf,  int[] inputBits) {
		
		//init values from input
		this.channel = channel;
		this.dlog = dlog;
		this.kdf = kdf;
		this.numberOfInputBits = inputBits.length;
		
		randomValues = new BigInteger[numberOfInputBits];
		this.inputBits = inputBits;
		h0Vector = new ArrayList<GroupElementSendableData>(numberOfInputBits);
		h1Vector = new ArrayList<GroupElementSendableData>(numberOfInputBits);
		result = new ArrayList<SecretKey>(numberOfInputBits);
		
		listOfRecievedValues = new LinkedList();
		
		
	}
	
	@Override
	/**
	 * runs the receiver side of the protocol
	 * 
	 * In general it does 3 main things
	 * 1. sample some values and sends them
	 * 2. Receives values from the sender
	 * 3. computes the relevant x0 or x1 for each index according to the related sigma.
	 */
	public void run() {
		
		//sample random values and set h0 and h1 for each value
		sampleRandomValuesAndSetHValues();
		
		//add h0Vector and h1Vector to a list and send it as a single message to the sender
		prepareListAndSend();
		
		//receive data from the sender and use it to compute the output. That is, the x_sigma for each value.
		receiveAndComputeOutput();
		
	}

	
	/**
	 * receives u,v0,v1 from the sender and uses these values to compute the output x_sigma for each index
	 * 
	 * From pseudocode : for each index do 
	 * WAIT for the message (u, v0,v1) from S //note that u is a single value 
	 * COMPUTE k_sigam = u^alpha //use exponentiateWithPreComputedValues since u is the same for all indices
	 * OUTPUT x_sigma = v_sigma XOR KDF(|v_sigma|,k_sigma)
	 */
	private void receiveAndComputeOutput() {
		
		//get the list of u,v0,v1 from the sender
		try {
			listOfRecievedValues = (LinkedList<ArrayList>) channel.receive();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
		
		//extract u,v0,v1 from the list
		ArrayList<GroupElementSendableData> uVector = listOfRecievedValues.get(0);
		ArrayList<byte[]> v0Vector =  listOfRecievedValues.get(1);
		ArrayList<byte[]> v1Vector = listOfRecievedValues.get(2);
		
		GroupElement u = dlog.generateElement(false, uVector.get(0));

		//a vector that will store the computed values k. Pseudocode: Compute K_sigma = U^alpha
		ArrayList<GroupElementSendableData> kVector = new ArrayList<GroupElementSendableData>();
		
		//the result for a single value of the OT, Meaning, x_sigma of the current index i
		byte[] subResult = null;
		
		
		for(int i=0; i<numberOfInputBits; i++){
			
			//TODO - use exponentiateWithPreComputedValues instead of just exponentiate when the function will work correctly
			
			kVector.add(dlog.exponentiateWithPreComputedValues(u, randomValues[i]).generateSendableData());
			//kVector.add(dlog.exponentiate(u, randomValues[i]).generateSendableData());
			
			//convert the groupElemet into byte[]
			byte[] groupElementBytes = dlog.mapAnyGroupElementToByteArray(dlog.generateElement(false, kVector.get(i)));
			byte[] rightHandEquation;//used for intermediate calculations
			byte[] v0Bytes = v0Vector.get(i);
			byte[] v1Bytes = v1Vector.get(i);
			
			//the size of the result should be the same size of v0 and v1. Initialize the size. 
			subResult = new byte[v0Bytes.length];
			
			
			
			if(inputBits[i]==0){
				//compute KDF(|v_sigma|,k)
				rightHandEquation = (kdf.derivateKey(groupElementBytes, 0, groupElementBytes.length, v0Vector.get(i).length)).getEncoded();
				
				//Xor the result of the KDF and v in order to get from the pseudocode the following "compute X_sigma = v_sigma XOR KDF(|v_sigma|,k)"
				for (int j = 0; j < rightHandEquation.length; j++)
		        {
					//Xor each byte
					subResult[j] = (byte) (rightHandEquation[j] ^ v0Bytes[j]);
		        }
			
			}else 
			{
				rightHandEquation = (kdf.derivateKey(groupElementBytes, 0, groupElementBytes.length, v1Vector.get(i).length)).getEncoded();
				//Xor the result of the KDF and v in order to get from the pseudocode the following "compute X_sigma = v_sigma XOR KDF(|v_sigma|,k)"
				for (int j = 0; j < rightHandEquation.length; j++)
		        {
					//Xor each byte
					subResult[j] = (byte) (rightHandEquation[j] ^ v1Bytes[j]);
		        }
			}
			
						
			//convert each subresult to SecretKey and put it in the vector that stores the final result for the whole batch OT
			result.add( new SecretKeySpec(subResult, ""));
		}
		
	}

	/**
	 * adds h0 and h1 to the list and sends the list as a single message 
	 */
	private void prepareListAndSend() {
		//make a list of the h vectors in order to send a single message
		LinkedList<ArrayList<GroupElementSendableData>> listOf2Vectors = new LinkedList<ArrayList<GroupElementSendableData>>();
		//add the 2 vectors to the list
		listOf2Vectors.add(h0Vector);
		listOf2Vectors.add(h1Vector);
		
		//send the 2 vectors to the sender. From pseudocode: "SEND (h0,h1) to S"
		try {
			channel.send(listOf2Vectors);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	/**
	 * samples random values and sets h0 and h1
	 * 
	 * From pseudocode: do for each index
	 * SAMPLE random values in alpha in Zq and h in G
	 * COMPUTE h0,h1 as follows:
     * 1. If sigma = 0 then h0 = g^alpha and h1=h
     * 2. If sigma = 1 then h0=h and h1 = g^alpha
	 */
	private void sampleRandomValuesAndSetHValues() {
		BigInteger one = BigInteger.ONE;
		BigInteger qMinusOne = dlog.getOrder().subtract(one);
		
		GroupElement generator = dlog.getGenerator();//get the generator g in the pseuodocode

		//SAMPLE random values in zq and  h in G
		for(int i=0;i<numberOfInputBits; i++){
			
			// choose a random number alpha in Zq
			randomValues[i] = BigIntegers.createRandomInRange(one, qMinusOne, new SecureRandom());
			
			
			if(inputBits[i]==0){//if the input bit is 0, than set h0 to be g^alpha and h1 to be the random element
				
				h0Vector.add(dlog.exponentiateWithPreComputedValues(generator, randomValues[i]).generateSendableData());
				//h0Vector.add(dlog.exponentiate(generator, randomValues[i]).generateSendableData());
				h1Vector.add(dlog.createRandomElement().generateSendableData());
				
			}else{//if the input bit is 1 than set h1 to be g^alpha and h0 to be the random element
				
				//h1Vector.set(i, dlog.exponentiateWithPreComputedValues(generator, randomValues[i]));
				//int cap = h0Vector.capacity();
				//h0Vector.setElementAt(dlog.createRandomElement(), i);
				
				h1Vector.add(dlog.exponentiateWithPreComputedValues(generator, randomValues[i]).generateSendableData());
				//h1Vector.add(dlog.exponentiate(generator, randomValues[i]).generateSendableData());
				h0Vector.add(dlog.createRandomElement().generateSendableData());
				
			}
				
		}
		
	}

	@Override
	public ProtocolOutput getOutput() {
		// TODO Auto-generated method stub
		return null;
	}

	public ArrayList<SecretKey> getResult() {
		return result;
	}

	
	

}
