package edu.biu.scapi.primitives.prf;

/** 
 * Marker interface. Every class that implements it is signed as AES.
 * AES is a blockCipher with fixed input and output lengths and thus implements the interface PrpFixed.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface AES extends PrpFixed {
}