package edu.biu.scapi.primitives.hash;

import edu.biu.scapi.securityLevel.CollisionResistant;

/** 
 * Marker interface. Every class that implements it is signed as SHA256.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface SHA256 extends CryptographicHash, CollisionResistant {
}