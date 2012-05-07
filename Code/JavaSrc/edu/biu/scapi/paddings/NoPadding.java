package edu.biu.scapi.paddings;

public class NoPadding implements PaddingScheme {

	@Override
	public byte[] pad(byte[] padInput, int padSize) {
		
		return padInput;
	}

	@Override
	public byte[] removePad(byte[] paddedInput) {
		
		return paddedInput;
	}

}
