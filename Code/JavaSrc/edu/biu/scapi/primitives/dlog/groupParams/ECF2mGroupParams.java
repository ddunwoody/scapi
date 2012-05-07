package edu.biu.scapi.primitives.dlog.groupParams;


/*
 * This class holds the parameters of an Elliptic curve over Z2m.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class ECF2mGroupParams extends ECGroupParams{

	protected int m; //specifying the finite field F2m
	
	/*
	 * Returns the number m that specifying the finite field F2m
	 * @return m
	 */
	public int getM(){
		return m;
	}
	
}
