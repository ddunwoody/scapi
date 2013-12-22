package edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension;



/**
 * A concrete class for ot extenstion input for the receiver. All the classes are the same and differ only in the name.
 * The reason a class is created for each version is due to the fact that a relative class is created for the sender and we wish
 * to be consistent. The name of the class determines the version of the ot extension we wish to run and in this case the correlated case.
 * 
 *  @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class OTExtensionRandomRInput extends OTExtensionRInput {

	public OTExtensionRandomRInput(byte[] sigmaArr, int elementSize) {
		super(sigmaArr, elementSize);
		// TODO Auto-generated constructor stub
	}

}
