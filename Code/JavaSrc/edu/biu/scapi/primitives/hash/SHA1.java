package edu.biu.scapi.primitives.hash;

import edu.biu.scapi.securityLevel.CollisionResistant;

/** 
 * Marker interface. Every class that implements it is signed as SHA1.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface SHA1 extends CryptographicHash, CollisionResistant{
}