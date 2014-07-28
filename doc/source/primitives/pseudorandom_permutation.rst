Pseudorandom Permutation (PRP)
==============================

**Pseudorandom permutations** are bijective pseudorandom functions that are *efficiently invertible*. As such, they are of the pseudorandom function type and their input length always equals their output length. In addition (and unlike general pseudorandom functions), they are efficiently invertible.

The ``PseudorandomPermutation`` Interface
-----------------------------------------

The ``PseudorandomPermutation`` interface extends the ``PseudorandomFunction`` interface, and adds the following functionality.

.. java:method:: public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff) throws IllegalBlockSizeException
   :outertype: PseudorandomPermutation

   Inverts the permutation using the given key.

   This function is a part of the PseudorandomPermutation interface since any PseudorandomPermutation must be efficiently invertible (given the key). For block ciphers, for example, the length is known in advance and so there is no need to specify the length.

   :param inBytes: input bytes to invert.
   :param inOff: input offset in the inBytes array
   :param outBytes: output bytes. The resulted bytes of invert
   :param outOff: output offset in the outBytes array to put the result from
   :throws IllegalBlockSizeException:

.. java:method:: public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff, int len) throws IllegalBlockSizeException
   :outertype: PseudorandomPermutation

   Inverts the permutation using the given key.

   Since PseudorandomPermutation can also have varying input and output length (although the input and the output should be the same length), the common parameter ``len`` of the input and the output is needed.

   :param inBytes: input bytes to invert.
   :param inOff: input offset in the inBytes array
   :param outBytes: output bytes. The resulted bytes of invert
   :param outOff: output offset in the outBytes array to put the result from
   :param len: the length of the input and the output
   :throws IllegalBlockSizeException:

Basic Usage
-----------

.. code-block:: java

    //Create secretKey and in, out, inv byte arrays
    ...
    
    //call the PrfFactory and cast to prp
    PseudorandomPermutation prp = (PseudorandomPermutation) PrfFactory.getInstance().getObject("OpenSSL", "AES");
    
    //set the key
    prp.setKey(secretKey);

    //run the permutation on a block-size prefix of in[]
    prp.computeBlock(in, 0, out, 0);

    //invert the permutation
    prp.invertBlock(out, 0, inv, 0);


Pseudorandom Permutation with Varying Input-Output Lengths
----------------------------------------------------------

A pseudorandom permutation with varying input/output lengths does not have pre-defined input/output lengths. The input and output length (that must be equal) may be different for each function call. The length of the input/output is determined upon user request.

We implement the `Luby-Rackoff algorithm`_ as an example of PRP with varying I/O lengths. The class that implements the algorithm is ``LubyRackoffPrpFromPrfVarying``.

.. _`Luby-Rackoff algorithm`:

How to use the Varying Input-Output Length PRP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: java

    //Create secretKey and in, out byte arrays
    ...
    
    //call the PrfFactory and cast to prp
    PseudorandomPermutation prp = (PseudorandomPermutation) PrfFactory.getInstance().getObject("LubyRackoffPrpFromPrfVarying");
    
    //set the key
    prp.setKey(secretKey);
    
    //invert the permutation with input in and output out of common size 20.
    prp.invertBlock(in, 0, out, 0, 20);
