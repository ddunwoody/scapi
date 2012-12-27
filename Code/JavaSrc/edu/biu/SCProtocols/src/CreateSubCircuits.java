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
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.Set;
import java.util.TreeSet;

import edu.biu.scapi.circuits.circuit.CircuitFileFormatException;


/**
 * This class takes a file containing a circuit in the format required by the BooleanCircuit class and breaks it into subcircuits, each in 
 * a different file. 
 * 
 * NOTE:
 * This class is incomplete and does not fit to any circuit for the following reasons.
 * 
 * 1. It assumes that the gates include only 2 inputs and 1 output and not general gates
 * 2. It also assumes that the first subcircuit contains the all the inputs and the last subcircuit contains all the outputs of the original circuit
 * 
 * In order for this class to work on any circuit these 2 issues should be resolved first.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class CreateSubCircuits {

	/**
	 * @param args
	 * @throws IOException 
	 * @throws CircuitFileFormatException 
	 */
	public static void main(String[] args) throws IOException, CircuitFileFormatException {
		
		final int numberOfSubCircuits = 5; 
		int numberOfGates;
		int numberOfCurrentGates;
		
		int[] in1 = null;
		int[] in2 = null;
		int[] out = null;
		String[] truthTable = null;
		
		ArrayList<Set<Integer>> inputs = new ArrayList<Set<Integer>>(numberOfSubCircuits);
		ArrayList<Set<Integer>> outputs = new ArrayList<Set<Integer>>(numberOfSubCircuits);
		ArrayList<ArrayList<Integer>> eachPartysInputWires = new ArrayList<ArrayList<Integer>>();
		
		
		File f = new File("AES_Final-2.txt");
		Scanner s = new Scanner(f);
		
		//get the number of gates from the header of the file
		numberOfGates = s.nextInt();
		
		 //get the number of wires. 
		 int numberOfWires = Integer.parseInt(s.next());
		 //get the number of parties
		 int numberOfParties =  Integer.parseInt(s.next());
		    
		 
		    for (int i = 0; i < numberOfParties; i++) {
		    	
		      //party number	 
		      if (Integer.parseInt(s.next()) != i+1) {//add 1 since parties are indexed from 1, not 0
		        throw new CircuitFileFormatException();
		      }
		      //
		      int numberOfInputsForCurrentParty = Integer.parseInt(s.next());
		      if(numberOfInputsForCurrentParty < 0){
		        throw new CircuitFileFormatException();
		      }
		      
		      ArrayList<Integer> currentPartyInput = new ArrayList<Integer>();
		      eachPartysInputWires.add(currentPartyInput);
		      for (int j = 0; j < numberOfInputsForCurrentParty; j++) {
		        currentPartyInput.add(Integer.parseInt(s.next()));
		      }
		    }
		    
		    //move over the outputs
		    int numberOfCircuitOutputs = Integer.parseInt(s.next());
		    for (int i = 0; i < numberOfCircuitOutputs; i++) {
		      s.next();
		    }
		
		numberOfCurrentGates = numberOfGates/numberOfSubCircuits;
		in1  = new int[numberOfGates];
		in2  = new int[numberOfGates];
		out  = new int[numberOfGates];
		truthTable = new String[numberOfGates];
		
		
		//get all the data of the gates. This will be put back to the relevant file later on.
		for (int i = 0; i < numberOfGates; i++) {
		      int numberOfGateInputs = s.nextInt();
		      int numberOfGateOutputs = s.nextInt();
		      
		      in1[i] = s.nextInt();
		      in2[i] = s.nextInt();
		      
		      out[i] = s.nextInt();
		      
		      truthTable[i] = s.next();
		}
		
		//calc all the inputs and the outputs
		for(int i=0; i<numberOfSubCircuits;i++){
			 
			inputs.add(createSubCircuitInputs(in1, in2, out, numberOfCurrentGates, i*(numberOfGates/numberOfSubCircuits)));
		}
		
		//calc the outputs
		for(int i=0; i<numberOfSubCircuits;i++){
			 
			outputs.add(createSubCircuitOutputs(in1, in2, out, numberOfCurrentGates, i, i*(numberOfGates/numberOfSubCircuits), inputs));
		}
		
		//create all the sub circuits files
		for(int j=0; j<numberOfSubCircuits;j++){
			
						
			//write to file
			FileWriter fstream = new FileWriter("out_" + j + ".txt");
			BufferedWriter outBuffer = new BufferedWriter(fstream);
			
			
			if(j!=0){//not the first instance
				
				//input is the output of the previous sub circuit
				outBuffer.write("" + numberOfCurrentGates + " " + (numberOfCurrentGates + inputs.get(j).size()) + "\n");
				outBuffer.write("2 \n");
				int size = inputs.get(j).size();
				outBuffer.write("1 " + size + "\n");//number of parties
				Object[] inputsArray = inputs.get(j).toArray();
				
				for(int i=0; i<size ; i++){
					outBuffer.write(((Integer) inputsArray[i]).toString() + "\n");
				}
				outBuffer.write("2 0 \n" );
				
			}
			else{ //the first file put back the inputs
				
				//the header of the file. Number of gates and wires
				outBuffer.write("" + numberOfCurrentGates + " " + (numberOfCurrentGates + (numberOfWires - numberOfGates )) + "\n");
				
				//write the number of parties. Only 2 parties.
				outBuffer.write("2 \n");
				if(eachPartysInputWires.size()==2){//the 2 parties have inputs
					
					//get the input wires of the first party
					ArrayList<Integer> party = eachPartysInputWires.get(0);
					int sizeOfParty = party.size();
					//write the first party input
					outBuffer.write("1 " +  sizeOfParty + "\n" );
					for(int i=0;i<sizeOfParty; i++){
						outBuffer.write(party.get(i) +  "\n" );
					}
					
					//get the input wires of the second party
					party = eachPartysInputWires.get(1);
					sizeOfParty = party.size();
					//write the second party input
					outBuffer.write("2 " +  sizeOfParty + "\n" );
					for(int i=0;i<sizeOfParty; i++){
						outBuffer.write(party.get(i) +  "\n" );
					}
				}
				else{ //there is only one party with inputs
					
					//get the first party inputs
					ArrayList<Integer> party = eachPartysInputWires.get(0);
					int sizeOfParty = party.size();
					//write the first party input
					outBuffer.write("1 " +  sizeOfParty + "\n" );
					for(int i=0;i<sizeOfParty; i++){
						outBuffer.write(party.get(i) +  "\n" );
					}
				}
					
			}
			
			Object[] outputsArray = outputs.get(j).toArray();
			int sizeOfOutputs = outputs.get(j).size();
			//outBuffer.write("2 0 \n" );
			outBuffer.write("\n" + sizeOfOutputs +"\n\n");
			for(int i=0; i<sizeOfOutputs ; i++){
				//write each output label
				outBuffer.write(((Integer) outputsArray[i]).toString() +  "\n");
			}	
			
			//write each gate
			int offset = j*(numberOfGates/numberOfSubCircuits);
			for (int i = offset; i < numberOfCurrentGates+offset; i++) {
				
				//2 inputs 1 output. This should be generalized to non-fixed inputs and outputs.
				outBuffer.write("2 1 ");
				outBuffer.write("" + in1[i]);
				outBuffer.write(" " + in2[i]);
				outBuffer.write(" " + out[i]);
				outBuffer.write(" " + truthTable[i] + "\n");
			}

			outBuffer.close();
			
		}
	}


	/**
	 * 
	 * calculates the inputs for the subcircuit
	 * @param in1
	 * @param in2
	 * @param out
	 * @param numberOfCurrentGates
	 * @param offset
	 * @return the inputs the subcircuit
	 */
	private static Set<Integer> createSubCircuitInputs(int[] in1, int[] in2, int[] out, int numberOfCurrentGates, int offset){
		
	
		//use TreeSet in so the set will be ordered
		Set<Integer> subCircuitInputs= new TreeSet<Integer>();
		
		//find the inputs
		for(int i=offset; i <numberOfCurrentGates + offset; i++){
			
			boolean isInput1 = true;
			boolean isInput2 = true;
			int input1 = in1[i];
			int input2 = in2[i];
		
			//run until the input's index. If the input appeared as an output before, it is not an input of this sub circuit,
			//rather, it is an inner wire
			for(int k=offset; k <i; k++){
				
				if(input1==out[k]){
					isInput1 = false;
				}
				if(input2==out[k]){
					isInput2 = false;
				}
			}
			
			//add an input to the input tree set
			if(isInput1){
				subCircuitInputs.add(new Integer(in1[i]));
			}
			if(isInput2){
				subCircuitInputs.add(new Integer(in2[i]));
			}
			
		}
		
		return subCircuitInputs;
		
	}
	
	/**
	 * Creates the subcircuits outputs of all the subcircuits 
	 * @param in1
	 * @param in2
	 * @param out
	 * @param numberOfCurrentGates
	 * @param offset
	 * @param inputs 
	 * @return
	 */
	private static Set<Integer> createSubCircuitOutputs(int[] in1, int[] in2, int[] out, int numberOfCurrentGates, int subcircuit, int offset, ArrayList<Set<Integer>> inputs){
		
		Set<Integer> subCircuitOutputs= new TreeSet<Integer>();
		
		for(int i=offset; i <numberOfCurrentGates + offset; i++){
			
			int input1 = in1[i];
			int input2 = in2[i];
			int output = out[i];
			boolean isOutput=true;
		
			
			//there is also an option that an output of a gate can be an output for the entire circuit
			//in that case it will not be in the inputs array of sets.
			
			for(int k=i;k<numberOfCurrentGates + offset;k++){
				
				if(output==in1[k] || output == in2[k]){
					isOutput = false;
				}
			}
		
			
			//An input to a gate as well as an output of a gate can be output for the subcircuit if it is an input for some subcircuit 
			//
			//go over the inputs for all the subcircuits and see if it is an input for some subcircuit
			
			for(int j=subcircuit + 1;j<inputs.size(); j++){
				
				if(inputs.get(j).contains(input1)){
					subCircuitOutputs.add(new Integer(input1));
				}
				if(inputs.get(j).contains(input2)){
					subCircuitOutputs.add(new Integer(input2));
				}
				if(isOutput == false){
					if(inputs.get(j).contains(output)){
						isOutput = true;
					}
				}
			
			}
			
			if(isOutput==true){
				subCircuitOutputs.add(new Integer(output));
			}
			
			
		}
		
		return subCircuitOutputs;
		
	}
	

}
