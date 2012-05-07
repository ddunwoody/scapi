package edu.biu.scapi.primitives.trapdoorPermutation;

/**
 * 
 * Enum that represent the possible validity values of trapdoor element.
 * There are three possible validity values: 
 * VALID (it is an element); 
 * NOT_VALID (it is not an element); 
 * DON’T_KNOW (there is not enough information to check if it is an element or not)
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public enum TPElValidity {
	VALID,
	NOT_VALID, 
	DONT_KNOW
}
