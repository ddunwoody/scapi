Pseudorandom Generator (PRG)
============================

A **pseudorandom generator (PRG)** is a deterministic algorithm that takes a “short” uniformly distributed string, known as *the seed*, and outputs a longer string that cannot be efficiently distinguished from a uniformly distributed string of that length.

The ``PseudorandomGenerator`` Interface
---------------------------------------

.. java:method:: public void getPRGBytes(byte[] outBytes, int outOffset, int outlen)

    Streams the prg bytes.
    
    :param outBytes: output bytes. The result of streaming the bytes.
    :param outOffset: output offset
    :param outlen: the required output length

Basic Usage
-----------

.. code-block:: java

    //Create secret key and out byte array
    ...
    
    //Create prg using the PrgFactory
    PseudorandomGenerator prg = PrgFactory.getInstance().getObject("RC4"); 
    SecretKey secretKey = prg.generateKey(256); //256 is the key size in bits. 
    
    //set the key
    Prg.setKey(secretKey);
    
    //get PRG bytes. The caller is responsible for allocating the out array.
    //The result will be put in the out array.
    prg.getPRGBytes(out.length, out);
