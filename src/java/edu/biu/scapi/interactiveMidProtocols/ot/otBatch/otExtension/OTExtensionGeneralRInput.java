package edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension;


/**
 * A concrete class for OT extension input for the receiver. <p>
 * All the classes are the same and differ only in the name.
 * The reason a class is created for each version is due to the fact that a respective class is created for the sender and we wish to be consistent. 
 * The name of the class determines the version of the OT extension we wish to run and in this case the general case.
 * 
 *  @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class OTExtensionGeneralRInput extends OTExtensionRInput {

	/**
	 * Constructor that sets the sigma array and the number of OT elements.
	 * @param sigmaArr An array of sigma for each OT.
	 * @param elementSize The size of each element in the OT extension, in bits. 
	 */
	public OTExtensionGeneralRInput(byte[] sigmaArr, int elementSize) {
		super(sigmaArr, elementSize);
	}

}
