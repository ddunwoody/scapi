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


package edu.biu.scapi.circuits.circuit;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.encryption.AESFixedKeyMultiKeyEncryption;
import edu.biu.scapi.circuits.encryption.HashingMultiKeyEncryption;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.circuits.garbledCircuit.FreeXORGarbledBooleanCircuit;
import edu.biu.scapi.circuits.garbledCircuit.FreeXORGate;
import edu.biu.scapi.circuits.garbledCircuit.GarbledBooleanCircuit;
import edu.biu.scapi.circuits.garbledCircuit.GarbledGate;
import edu.biu.scapi.circuits.garbledCircuit.GarbledWire;
import edu.biu.scapi.circuits.garbledCircuit.MinimizeAESSetKeyGarbledBooleanCircuit;
import edu.biu.scapi.circuits.garbledCircuit.MinimizeAESSetKeyGarbledGate;
import edu.biu.scapi.circuits.garbledCircuit.StandardGarbledBooleanCircuit;
import edu.biu.scapi.circuits.garbledCircuit.StandardGarbledGate;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.primitives.prf.PseudorandomFunction;
import edu.biu.scapi.primitives.prf.cryptopp.CryptoPpAES;

public class test {
  public static void main(String... args) throws Exception {
    // garbledGateTest();
    // AESMESTest();
    // System.out.println(getSignalBit(new byte[]{1,2,3,4}));
    // garbledGateTest();
    regularCicruitfromFileTest();
    hashTest();
    AES128Test();
    minimizeAESSetKeyGarbledCircuitTest();
     minimizeAESSetKeyGarbledGateTest();
     AESFixedTest();
     freeXORWithHashingTest();
     freeXORWithFixedKeyTest();

// Scanner s = new Scanner(System.in);
    // System.out.println(s.nextInt(2));
    // garbledGateVerifyTest();
    // ungarbledCircuitTest();
    // long startTime = System.nanoTime();
    // Scanner sc = new Scanner(new File("AES_Final-2.txt"));
    // while (sc.hasNext()) {
    // sc.next();
    // }
    // long endTime = System.nanoTime();
    // System.out.println("Took " + (endTime - startTime) * .000000001
    // + " just to read the file and do nothing with it");
    // hashTest();
    // garbledCircuitVerifyTest();
    // garbledCircuitVerifyTest();
    // freeXORTest();
    // freeXORGarbledCircuitVerifyTest();
  }

  static void ungarbledCircuitTest() throws Exception {
    long startTime = System.nanoTime();
    BooleanCircuit bc = new BooleanCircuit(new File("AES_Final-2.txt"));
    long endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to create the ungarbled curcuit.");
    // bc.setInputs(new File("AESinputs.txt"));
    // Map<Integer, Wire> outputMap = bc.compute();
    // for(int w: bc.getOutputWireLabels()){
    // System.out.print(outputMap.get(w).getValue());
    // }
    // System.out.println();

  }

  static void FreeXORGateTest() throws Exception {
    HashingMultiKeyEncryption mes = new HashingMultiKeyEncryption();
    // MultiKeyEncryptionScheme mes = new AESFixedKeyMultiKeyEncryption();

    XORGate ungarbled = new XORGate(1, new int[] { 1, 2 }, new int[] { 3 });
    Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
    SecretKey onevalue0 = mes.generateKey();
    SecretKey onevalue1 = mes.generateKey();
    SecretKey twovalue0 = mes.generateKey();
    SecretKey twovalue1 = mes.generateKey();
    SecretKey threevalue0 = mes.generateKey();
    SecretKey threevalue1 = mes.generateKey();

    Map<Integer, Integer> signalBits = new HashMap<Integer, Integer>();
    signalBits.put(1, 0);
    byte[] a = onevalue0.getEncoded();
    a[onevalue0.getEncoded().length - 1] &= 254;
    byte[] b = onevalue1.getEncoded();
    b[onevalue1.getEncoded().length - 1] |= 1;
    onevalue0 = new SecretKeySpec(a, "");
    onevalue1 = new SecretKeySpec(b, "");

    signalBits.put(2, 0);
    byte[] c = twovalue0.getEncoded();
    c[twovalue0.getEncoded().length - 1] &= 254;
    byte[] d = twovalue1.getEncoded();
    d[twovalue1.getEncoded().length - 1] |= 1;
    twovalue0 = new SecretKeySpec(c, "");
    twovalue1 = new SecretKeySpec(d, "");
    allWireValues.put(1, new SecretKey[] { onevalue0, onevalue1 });
    allWireValues.put(2, new SecretKey[] { twovalue0, twovalue1 });
    allWireValues.put(3, new SecretKey[] { threevalue0, threevalue1 });

    FreeXORGate g = new FreeXORGate(ungarbled);
    Map<Integer, GarbledWire> computedWires = new HashMap<Integer, GarbledWire>();
    System.out.println("threevalue0: " + threevalue0.getEncoded()[0]);
    System.out.println("threevalue1: " + threevalue1.getEncoded()[0]);

    // System.out.println(t.getBytes()[0]);
    computedWires.put(1, new GarbledWire(1, onevalue1));
    computedWires.put(2, new GarbledWire(2, twovalue1));
    g.compute(computedWires);
    GarbledWire answer = computedWires.get(3);
    System.out.println("computed answer: "
        + answer.getValueAndSignalBit().getEncoded()[0]);

    /*
     * mes.setKey(mes.generateMultiKey(onevalue0,twovalue0));
     * SymmetricCiphertext encryptedThreeValue0 = mes.encrypt(new
     * ByteArrayPlaintext(threevalue0.getEncoded())); ByteArrayPlaintext bap =
     * (ByteArrayPlaintext)(mes.decrypt(encryptedThreeValue0));
     * System.out.println("manually encrypted/decrypted: " + bap.getText()[0]);
     */

  }

  static void HashingMESTest() throws Exception {

    MultiKeyEncryptionScheme mes = new HashingMultiKeyEncryption();

    ByteArrayPlaintext b = new ByteArrayPlaintext(new byte[] { 1, 2, 3, 7, 9,
        4, 5 });
    mes.setKey(mes.generateMultiKey(mes.generateKey(), mes.generateKey(),
        mes.generateKey()));
    ByteArrayPlaintext decrypted = (ByteArrayPlaintext) (mes.decrypt(mes
        .encrypt(b)));
    for (byte i : decrypted.getText()) {
      System.out.println(i);
    }

  }

  static void AESMESTest() throws Exception {

    MultiKeyEncryptionScheme mes = new AESFixedKeyMultiKeyEncryption();

    ByteArrayPlaintext b = new ByteArrayPlaintext(new byte[] { 1, 2, 3, 7, 9,
        4, 5, 6, 4, 3, 21, 12, 4, 3, 2, 1 });
    mes.setKey(mes.generateMultiKey(mes.generateKey(), mes.generateKey(),
        mes.generateKey()));
    ByteArrayPlaintext decrypted = (ByteArrayPlaintext) (mes.decrypt(mes
        .encrypt(b)));
    for (byte i : decrypted.getText()) {
      System.out.print(i);
    }

  }

  public static int getSignalBit(byte[] v) {
    int signalBit = (v[v.length - 1] & 1) == 0 ? 0 : 1;
    return signalBit;
  }

  static void freeXORWithFixedKeyTest() throws Exception {
    System.out.println("Free XOR with AES fixed key");
    BooleanCircuit bc = new BooleanCircuit(new File("AES_Final-2.txt"));
    
    // MultiKeyEncryptionScheme mes = new AES128MultiKeyEncryption();
    MultiKeyEncryptionScheme mes = new AESFixedKeyMultiKeyEncryption();
    Map<Integer, SecretKey[]> allInputWireValues = new HashMap<Integer, SecretKey[]>();
    long startTime = System.nanoTime();
    GarbledBooleanCircuit gbc = new FreeXORGarbledBooleanCircuit(bc, mes, allInputWireValues);
    long endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to create the circuit and generate inputs.");
    startTime = System.nanoTime();
    gbc.setGarbledInputFromUngarbledFile(new File("AESInputs.txt"),
        allInputWireValues);
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to read the input from a file and set the input.");
    startTime = System.nanoTime();
    Map<Integer, GarbledWire> garbledOutput = gbc.compute();
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to compute the circuit.");
    startTime = System.nanoTime();
    gbc.translate(garbledOutput);
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to translate the output.");

  }
  static void freeXORWithHashingTest() throws Exception {
    System.out.println("Free XOR with hashing (80 bits)");
    BooleanCircuit bc = new BooleanCircuit(new File("AES_Final-2.txt"));
    
    MultiKeyEncryptionScheme mes = new HashingMultiKeyEncryption(80);
    Map<Integer, SecretKey[]> allInputWireValues = new HashMap<Integer, SecretKey[]>();
    long startTime = System.nanoTime();
    GarbledBooleanCircuit gbc = new FreeXORGarbledBooleanCircuit(bc, mes, allInputWireValues);
    long endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to create the circuit and generate inputs.");
    startTime = System.nanoTime();
    gbc.setGarbledInputFromUngarbledFile(new File("AESInputs.txt"),
        allInputWireValues);
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to read the input from a file and set the input.");
    startTime = System.nanoTime();
    Map<Integer, GarbledWire> garbledOutput = gbc.compute();
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to compute the circuit.");
    startTime = System.nanoTime();
    gbc.translate(garbledOutput);
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to translate the output.");

  }

  static void hashTest() throws Exception {
    System.out.println("Using Hashing");
    BooleanCircuit bc = new BooleanCircuit(new File("AES_Final-2.txt"));
    MultiKeyEncryptionScheme mes = new HashingMultiKeyEncryption(80);
    Map<Integer, SecretKey[]> allInputWireValues = new HashMap<Integer, SecretKey[]>();
    long startTime = System.nanoTime();
    GarbledBooleanCircuit gbc = new StandardGarbledBooleanCircuit(bc, mes, allInputWireValues);
    long endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to create the circuit and generate inputs.");
    startTime = System.nanoTime();
    gbc.setGarbledInputFromUngarbledFile(new File("AESInputs.txt"),
        allInputWireValues);
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to read the input from a file and set the input.");
    startTime = System.nanoTime();
    Map<Integer, GarbledWire> garbledOutput = gbc.compute();
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to compute the circuit.");
    startTime = System.nanoTime();
    gbc.translate(garbledOutput);
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to translate the output.");

  }

  static void garbledCircuitVerifyTest() throws Exception {
    BooleanCircuit bc = new BooleanCircuit(new File("AES_Final-2.txt"));
    BooleanCircuit cc = new BooleanCircuit(new File("AES_Final-3.txt"));
    MultiKeyEncryptionScheme mes = new HashingMultiKeyEncryption();
    Map<Integer, SecretKey[]> allInputWireValues = new HashMap<Integer, SecretKey[]>();
    StandardGarbledBooleanCircuit gbc = new StandardGarbledBooleanCircuit(bc, mes,
        allInputWireValues);
    System.out.println(gbc.verify(bc, allInputWireValues));
    System.out.println(allInputWireValues.size());
    // System.out.println(gbc.verify(cc, allInputWireValues));

  }

  static void freeXORGarbledCircuitVerifyTest() throws Exception {
    BooleanCircuit bc = new BooleanCircuit(new File("AES_Final-2.txt"));
    BooleanCircuit cc = new BooleanCircuit(new File("AES_Final-3.txt"));
    MultiKeyEncryptionScheme mes = new HashingMultiKeyEncryption();
    Map<Integer, SecretKey[]> allInputWireValues = new HashMap<Integer, SecretKey[]>();
    FreeXORGarbledBooleanCircuit gbc = new FreeXORGarbledBooleanCircuit(bc,
        mes, allInputWireValues);
    System.out.println(gbc.verify(bc, allInputWireValues));
    System.out.println(allInputWireValues.size());
    System.out.println(gbc.verify(cc, allInputWireValues));

  }

  static void AESFixedTest() throws Exception {
    System.out.println("Using Fixed AES:");
    BooleanCircuit bc = new BooleanCircuit(new File("AES_Final-2.txt"));
    Map<Integer, SecretKey[]> allInputWireValues = new HashMap<Integer, SecretKey[]>();
    MultiKeyEncryptionScheme mes = new AESFixedKeyMultiKeyEncryption();
    long startTime = System.nanoTime();
    GarbledBooleanCircuit gbc = new StandardGarbledBooleanCircuit(bc, mes, allInputWireValues);
    long endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to create the circuit and generate inputs.");
    startTime = System.nanoTime();
    gbc.setGarbledInputFromUngarbledFile(new File("AESInputs.txt"),
        allInputWireValues);
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to read the input from a file and set the input.");
    startTime = System.nanoTime();
    Map<Integer, GarbledWire> garbledOutput = gbc.compute();
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to compute the circuit.");
    startTime = System.nanoTime();
    gbc.translate(garbledOutput);
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to translate the output.");
  }

  static void AES128Test() throws Exception {
    System.out.println("Using AES128 naive(i.e. does not minimize setKey operations:");
    BooleanCircuit bc = new BooleanCircuit(new File("AES_Final-2.txt"));
    MultiKeyEncryptionScheme mes = new AESFixedKeyMultiKeyEncryption();
    Map<Integer, SecretKey[]> allInputWireValues = new HashMap<Integer, SecretKey[]>();
    long startTime = System.nanoTime();
    GarbledBooleanCircuit gbc = new StandardGarbledBooleanCircuit(bc, mes, allInputWireValues);
    long endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to create the circuit and generate inputs.");
    startTime = System.nanoTime();
    gbc.setGarbledInputFromUngarbledFile(new File("AESInputs.txt"),
        allInputWireValues);
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to read the input from a file and set the input.");
    startTime = System.nanoTime();
    Map<Integer, GarbledWire> garbledOutput = gbc.compute();
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to compute the circuit.");
    startTime = System.nanoTime();
    gbc.translate(garbledOutput);
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to translate the output.");

  }

  static void minimizeAESSetKeyGarbledCircuitTest() throws Exception {
    System.out.println("Using AES128 with minimal setKey operations:");
    BooleanCircuit bc = new BooleanCircuit(new File("AES_Final-2.txt"));
    long startTime = System.nanoTime();
    Map<Integer, SecretKey[]> allInputWireValues = new HashMap<Integer, SecretKey[]>();
    // GarbledBooleanCircuit gbc = new StandardGarbledBooleanCircuit(bc, mes,
    // allInputWireValues);
    GarbledBooleanCircuit gbc = new MinimizeAESSetKeyGarbledBooleanCircuit(bc,
        allInputWireValues);
    System.out.println(gbc.verify(bc, allInputWireValues));
    long endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to create the circuit and generate inputs.");
    startTime = System.nanoTime();
    gbc.setGarbledInputFromUngarbledFile(new File("AESInputs.txt"),
        allInputWireValues);
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to read the input from a file and set the input.");
    startTime = System.nanoTime();
    Map<Integer, GarbledWire> garbledOutput = gbc.compute();
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to compute the circuit.");
    startTime = System.nanoTime();
    gbc.translate(garbledOutput);
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to translate the output.") ;
        }

  static void garbledGateTest() throws Exception {
    // HashingMultiKeyEncryption mes = new HashingMultiKeyEncryption();
    MultiKeyEncryptionScheme mes = new AESFixedKeyMultiKeyEncryption();
    ANDGate ungarbled = new ANDGate(1, new int[] { 1, 2 }, new int[] { 3 });
    Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
    SecretKey onevalue0 = mes.generateKey();
    SecretKey onevalue1 = mes.generateKey();
    SecretKey twovalue0 = mes.generateKey();
    SecretKey twovalue1 = mes.generateKey();
    SecretKey threevalue0 = mes.generateKey();
    SecretKey threevalue1 = mes.generateKey();

    Map<Integer, Integer> signalBits = new HashMap<Integer, Integer>();
    signalBits.put(1, 0);
    byte[] a = onevalue0.getEncoded();
    a[onevalue0.getEncoded().length - 1] &= 254;
    byte[] b = onevalue1.getEncoded();
    b[onevalue1.getEncoded().length - 1] |= 1;
    onevalue0 = new SecretKeySpec(a, "");
    onevalue1 = new SecretKeySpec(b, "");

    signalBits.put(2, 0);
    byte[] c = twovalue0.getEncoded();
    c[twovalue0.getEncoded().length - 1] &= 254;
    byte[] d = twovalue1.getEncoded();
    d[twovalue1.getEncoded().length - 1] |= 1;
    twovalue0 = new SecretKeySpec(c, "");
    twovalue1 = new SecretKeySpec(d, "");
    allWireValues.put(1, new SecretKey[] { onevalue0, onevalue1 });
    allWireValues.put(2, new SecretKey[] { twovalue0, twovalue1 });
    allWireValues.put(3, new SecretKey[] { threevalue0, threevalue1 });

    StandardGarbledGate g = new StandardGarbledGate(mes, ungarbled,
        allWireValues, signalBits);
    Map<Integer, GarbledWire> computedWires = new HashMap<Integer, GarbledWire>();
    System.out.println("threevalue0: " + threevalue0.getEncoded()[0]);
    System.out.println("threevalue1: " + threevalue1.getEncoded()[0]);

    // System.out.println(t.getBytes()[0]);
    computedWires.put(1, new GarbledWire(1, onevalue1));
    computedWires.put(2, new GarbledWire(2, twovalue1));
    g.compute(computedWires);
    GarbledWire answer = computedWires.get(3);
    System.out.println("computed answer: "
        + answer.getValueAndSignalBit().getEncoded()[0]);

    /*
     * mes.setKey(mes.generateMultiKey(onevalue0,twovalue0));
     * SymmetricCiphertext encryptedThreeValue0 = mes.encrypt(new
     * ByteArrayPlaintext(threevalue0.getEncoded())); ByteArrayPlaintext bap =
     * (ByteArrayPlaintext)(mes.decrypt(encryptedThreeValue0));
     * System.out.println("manually encrypted/decrypted: " + bap.getText()[0]);
     */

  }

  static void minimizeAESSetKeyGarbledGateTest() throws Exception {
    // HashingMultiKeyEncryption mes = new HashingMultiKeyEncryption();
    MultiKeyEncryptionScheme mes = new AESFixedKeyMultiKeyEncryption();
    ANDGate ungarbled = new ANDGate(1, new int[] { 1, 2 }, new int[] { 3 });
    Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
    SecretKey onevalue0 = mes.generateKey();
    SecretKey onevalue1 = mes.generateKey();
    SecretKey twovalue0 = mes.generateKey();
    SecretKey twovalue1 = mes.generateKey();
    SecretKey threevalue0 = mes.generateKey();
    SecretKey threevalue1 = mes.generateKey();

    Map<Integer, Integer> signalBits = new HashMap<Integer, Integer>();
    signalBits.put(1, 0);
    byte[] a = onevalue0.getEncoded();
    a[onevalue0.getEncoded().length - 1] &= 254;
    byte[] b = onevalue1.getEncoded();
    b[onevalue1.getEncoded().length - 1] |= 1;
    onevalue0 = new SecretKeySpec(a, "");
    onevalue1 = new SecretKeySpec(b, "");

    signalBits.put(2, 0);
    byte[] c = twovalue0.getEncoded();
    c[twovalue0.getEncoded().length - 1] &= 254;
    byte[] d = twovalue1.getEncoded();
    d[twovalue1.getEncoded().length - 1] |= 1;
    twovalue0 = new SecretKeySpec(c, "");
    twovalue1 = new SecretKeySpec(d, "");
    allWireValues.put(1, new SecretKey[] { onevalue0, onevalue1 });
    allWireValues.put(2, new SecretKey[] { twovalue0, twovalue1 });
    allWireValues.put(3, new SecretKey[] { threevalue0, threevalue1 });

    
    //this will be passed to the gates for encryption
    PseudorandomFunction aes = new CryptoPpAES();

    /*this will be passed to the gates and used for decryption and (for now) verifying. Eventually, verifying willl
    *also minimze seKEy operations and use aes directly
    */
    //MultiKeyEncryptionScheme mes = new AES128MultiKeyEncryption();
    
    
    GarbledGate g = new MinimizeAESSetKeyGarbledGate(ungarbled, allWireValues, signalBits, mes, aes );
    Map<Integer, GarbledWire> computedWires = new HashMap<Integer, GarbledWire>();
    System.out.println("threevalue0: " + threevalue0.getEncoded()[0]);
    System.out.println("threevalue1: " + threevalue1.getEncoded()[0]);

    // System.out.println(t.getBytes()[0]);
    computedWires.put(1, new GarbledWire(1, onevalue1));
    computedWires.put(2, new GarbledWire(2, twovalue1));
    g.compute(computedWires);
    GarbledWire answer = computedWires.get(3);
    System.out.println("computed answer: "
        + answer.getValueAndSignalBit().getEncoded()[0]);

    /*
     * mes.setKey(mes.generateMultiKey(onevalue0,twovalue0));
     * SymmetricCiphertext encryptedThreeValue0 = mes.encrypt(new
     * ByteArrayPlaintext(threevalue0.getEncoded())); ByteArrayPlaintext bap =
     * (ByteArrayPlaintext)(mes.decrypt(encryptedThreeValue0));
     * System.out.println("manually encrypted/decrypted: " + bap.getText()[0]);
     */

  }

  static void AESOneGATEtest() throws Exception {
    MultiKeyEncryptionScheme mes = new AESFixedKeyMultiKeyEncryption();
    ANDGate ungarbled = new ANDGate(1, new int[] { 1, 2 }, new int[] { 3 });
    Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
    SecretKey onevalue0 = mes.generateKey();
    SecretKey onevalue1 = mes.generateKey();
    SecretKey twovalue0 = mes.generateKey();
    SecretKey twovalue1 = mes.generateKey();
    SecretKey threevalue0 = mes.generateKey();
    SecretKey threevalue1 = mes.generateKey();

    Map<Integer, Integer> signalBits = new HashMap<Integer, Integer>();
    signalBits.put(1, 0);
    byte[] a = onevalue0.getEncoded();
    a[onevalue0.getEncoded().length - 1] &= 254;
    byte[] b = onevalue1.getEncoded();
    b[onevalue1.getEncoded().length - 1] |= 1;
    onevalue0 = new SecretKeySpec(a, "");
    onevalue1 = new SecretKeySpec(b, "");

    signalBits.put(2, 0);
    byte[] c = twovalue0.getEncoded();
    c[twovalue0.getEncoded().length - 1] &= 254;
    byte[] d = twovalue1.getEncoded();
    d[twovalue1.getEncoded().length - 1] |= 1;
    twovalue0 = new SecretKeySpec(c, "");
    twovalue1 = new SecretKeySpec(d, "");
    allWireValues.put(1, new SecretKey[] { onevalue0, onevalue1 });
    allWireValues.put(2, new SecretKey[] { twovalue0, twovalue1 });
    allWireValues.put(3, new SecretKey[] { threevalue0, threevalue1 });
    long startTime = System.nanoTime();
    StandardGarbledGate g = new StandardGarbledGate(mes, ungarbled,
        allWireValues, signalBits);
    long endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to garble a single gate.");
    Map<Integer, GarbledWire> computedWires = new HashMap<Integer, GarbledWire>();
    System.out.println("threevalue0: " + threevalue0.getEncoded()[0]);
    System.out.println("threevalue1: " + threevalue1.getEncoded()[0]);

    // System.out.println(t.getBytes()[0]);
    computedWires.put(1, new GarbledWire(1, onevalue1));
    computedWires.put(2, new GarbledWire(2, twovalue1));
    startTime = System.nanoTime();
    g.compute(computedWires);
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to compute a single gate.");
  }

  static void gateVerifyTest() {
    Gate and = new ANDGate(1, new int[] { 1, 2 }, new int[] { 3 });
    Gate or = new ORGate(1, new int[] { 1, 2 }, new int[] { 3 });
    System.out.println(and.verify(or));
    // StandardGarbledGate garbledAND = new StandardGarbledGate(and);
  }

  static void garbledGateVerifyTest() throws Exception {
    Gate ungarbledAND = new ANDGate(1, new int[] { 1, 2 }, new int[] { 3 });
    Gate ungarbledOR = new ORGate(1, new int[] { 1, 2 }, new int[] { 3 });
    MultiKeyEncryptionScheme mes = new HashingMultiKeyEncryption();
    Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
    SecretKey onevalue0 = mes.generateKey();
    SecretKey onevalue1 = mes.generateKey();
    SecretKey twovalue0 = mes.generateKey();
    SecretKey twovalue1 = mes.generateKey();
    SecretKey threevalue0 = mes.generateKey();
    SecretKey threevalue1 = mes.generateKey();

    Map<Integer, Integer> signalBits = new HashMap<Integer, Integer>();
    signalBits.put(1, 0);
    byte[] a = onevalue0.getEncoded();
    a[onevalue0.getEncoded().length - 1] &= 254;
    byte[] b = onevalue1.getEncoded();
    b[onevalue1.getEncoded().length - 1] |= 1;
    onevalue0 = new SecretKeySpec(a, "");
    onevalue1 = new SecretKeySpec(b, "");

    signalBits.put(2, 0);
    byte[] c = twovalue0.getEncoded();
    c[twovalue0.getEncoded().length - 1] &= 254;
    byte[] d = twovalue1.getEncoded();
    d[twovalue1.getEncoded().length - 1] |= 1;
    twovalue0 = new SecretKeySpec(c, "");
    twovalue1 = new SecretKeySpec(d, "");
    allWireValues.put(1, new SecretKey[] { onevalue0, onevalue1 });
    allWireValues.put(2, new SecretKey[] { twovalue0, twovalue1 });
    allWireValues.put(3, new SecretKey[] { threevalue0, threevalue1 });
    StandardGarbledGate garbledAND = new StandardGarbledGate(mes, ungarbledAND,
        allWireValues, signalBits);
    System.out.println(garbledAND.verify(ungarbledOR, allWireValues));
  }
  static void regularCicruitfromFileTest() throws IOException, ClassNotFoundException{
    System.out.println("Times to create a regular circuit:");
    long startTime = System.nanoTime();
    BooleanCircuit bc = new BooleanCircuit(new File("AES_Final-2.txt"));
  
    long endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to create the circuit from the file.");
    ObjectOutput oos = new ObjectOutputStream(new FileOutputStream("myCircuit.txt"));
    oos.writeObject(bc);
    oos.close();
    startTime = System.nanoTime();
    ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File("myCircuit.txt")));
    // Deserialize the object
    BooleanCircuit deserializedBC = (BooleanCircuit) ois.readObject();
    ois.close();
    endTime = System.nanoTime();
    System.out.println("Took " + (endTime - startTime) * .000000001
        + " seconds to deserialize the circuit from the file.");
  }
}
