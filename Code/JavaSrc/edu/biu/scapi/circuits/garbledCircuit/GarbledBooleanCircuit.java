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

import java.util.Map;

import edu.biu.scapi.circuits.circuit.Wire;

/**
 * {@code GarbledBooleanCircuit} is a general interface implemented by all
 * garbled circuits--optimized or not. 
 * The difference between a sub circuit and a circuit is that a sub circuit does not have the 
 * ability to translate the output of compute into a result using some kind of translation from 
 * keys to 0/1 output since the translation table simply does not exist. The reason is that 
 * letting a party compute the result on several steps on the way to the final result may 
 * leak some information and thus not possible. A circuit, on the other way must have the 
 * functionality of translating the computed result into a 0/1 result which is the output
 * of the function we wish to compute. The circuit interface add the functionality of translate.
 * All garbled circuits have the added function {@link #translate(Map)} that  
 * translates the garbled output from {@link #compute()} into meaningful output.
 * 
 * @author Steven Goldfeder
 * 
 */
public interface GarbledBooleanCircuit extends GarbledBooleanSubCircuit{
  

  /**
   * Translates the garbled output obtained from the {@link #compute()} function
   * into meaningful(i.e. 0-1) output.
   * 
   * @param garbledOutput
   *          a {@code Map) that containing the garbled output. This map maps
   *          the output wire labels to {@code GarbledWire}s
   * @return a {@code Map} that maps the output wire labels to ungarbled
   *         {@code Wire}s that are set to either 0 or 1.
   */
  public Map<Integer, Wire> translate(Map<Integer, GarbledWire> garbledOutput);

  
  /**
   * Returns the translation table of the circuit. This is necessary since the conrtructor of the circuit may want to pass the
   * translation table to other party. Usually, this will be used when the other party (not the constructor of the circuit) 
   * sets the garbled tables and needs the translation table as well to complete the construction of the circuit
   * 
   * @return The translation table of the circuit.  
   *           
   */
  public Map<Integer, Integer> getTranslationTable();
  
  
/**
 * Sets the translation table of the circuit. This is necessary when the garbled tables where set and we would like to 
 * compute the circuit later on. 
 * @param translationTable
 */
  public void setTranslationTable(Map<Integer, Integer> translationTable);
}
