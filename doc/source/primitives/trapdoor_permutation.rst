Trapdoor Permutation
====================

A trapdoor permutation is a bijection (1-1 and onto function) that is easy to compute for everyone, yet is hard to invert unless given special additional information, called the "trapdoor". The public key is essentially the function description and the private key is the trapdoor. 

.. contents::

The ``TPElement`` Interface
---------------------------

The ``TPElement`` interface represents a trapdoor permutation element.

.. java:method:: public BigInteger getElement()

    Returns the trapdoor element value as BigInteger.
    
    :return: the value of the element

.. java:method:: public TPElementSendableData generateSendableData()
    
    This function extracts the actual value of the TPElement and wraps it in a TPElementSendableData that as it name indicates can be send using the serialization mechanism.
    
    :return: A Serializable representation of the TPElement

The ``TrapdoorPermutation`` Interface
-------------------------------------

This interface is the general interface of trapdoor permutation.

Core Functionality
~~~~~~~~~~~~~~~~~~

.. java:method:: public TPElement compute(TPElement tpEl)
 
    Computes the operation of this trapdoor permutation on the given TPElement.

    :param tpEl: the input for the computation
    :return: the result TPElement from the computation
    :throws: IllegalArgumentException if the given element is invalid for this permutation

.. java:method:: public TPElement invert(TPElement tpEl)

    Inverts the operation of this trapdoor permutation on the given TPElement.

    :param tpEl: the input to invert
    :return: the result TPElement from the invert operation
    :throws: KeyException if there is no private key
    :throws: IllegalArgumentException if the given element is invalid for this permutation

.. java:method:: public byte hardCorePredicate(TPElement tpEl)

    Computes the hard core predicate of the given tpElement.
    
    A hard-core predicate of a one-way function :math:`f` is a predicate :math:`b` (i.e., a function whose output is a single bit) 
    which is easy to compute given :math:`x` but is hard to compute given :math:`f(x)`.
    In formal terms, there is no probabilistic polynomial time algorithm that computes :math:`b(x)` from :math:`f(x)` 
    with probability significantly greater than one half over random choice of :math:`x`.

    :param tpEl: the input to the hard core predicate
    :return: (byte) the hard core predicate.

.. java:method:: public byte[] hardCoreFunction(TPElement tpEl)

    Computes the hard core function of the given tpElement.

    A hard-core function of a one-way function :math:`f` is a function :math:`g` 
    which is easy to compute given :math:`x` but is hard to compute given :math:`f(x)`.
    In formal terms, there is no probabilistic polynomial time algorithm that computes :math:`g(x)` from :math:`f(x)` 
    with probability significantly greater than one half over random choice of :math:`x`.

    :param tpEl: the input to the hard core function
    :return: byte[] the result of the hard core function


Generating TPElements
~~~~~~~~~~~~~~~~~~~~~

.. java:method:: public TPElement generateRandomTPElement()

    creates a random TPElement that is valid for this trapdoor permutation

    :return: the created random element 

.. java:method:: public TPElement generateTPElement(BigInteger x)

    Creates a TPElement from a specific value :math:`x`. 
    It checks that the :math:`x` value is valid for this trapdoor permutation.

    :return: If the :math:`x` value is valid for this permutation return the created random element
    :throws:  IllegalArgumentException if the given value :math:`x` is invalid for this permutation

.. java:method:: public TPElement generateUncheckedTPElement(BigInteger x)
 
    Creates a TPElement from a specific value :math:`x`. 
    This function does not guarantee that the the returned ``TPElement`` object is valid.
    It is the caller's responsibility to pass a legal :math:`x` value.

    :return: Set the :math:`x` value and return the created random element

.. java:method:: public TPElement reconstructTPElement(TPElementSendableData data)

    Creates a TPElement from data that was probably obtained via the serialization mechanism.
    
    :param data: serialized data necessary to reconstruct a given TPElement
    :return: the reconstructed TPElement

Checking Element Validity
~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:method:: public TPElValidity isElement(TPElement tpEl)

    Checks if the given element is valid for this trapdoor permutation

    :param tpEl: the element to check
    :return: (`TPElValidity`_) enum number that indicate the validation of the element
    :throws: IllegalArgumentException if the given element is invalid for this permutation

.. _TPElValidity:

.. java:type:: public enum TPElValidity

    Enum that represent the possible validity values of trapdoor element.
    There are three possible validity values:

    :param VALID: it is an element
    :param NOT_VALID: it is not an element
    :param DONT_KNOW: there is not enough information to check if it is an element or not

Encryption Keys Functionality
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:method:: public void setKey(PublicKey publicKey, PrivateKey privateKey)

    Sets this trapdoor permutation with public key and private key.

    :param publicKey: the public key
    :param privateKey: the private key that without it the permutation cannot be inverted efficiently
	
.. java:method:: public void setKey(PublicKey publicKey)

    Sets this trapdoor permutation with a public key.    
    After this initialization, this object can do ``compute()`` but not ``invert()``.
    This initialization is for user that wants to encrypt messages using the public key but cannot decrypt messages.

    :param publicKey: the public key
    :throws: InvalidKeyException if the key is not a valid key of this permutation

.. java:method:: public boolean isKeySet()
    
    Checks if this trapdoor permutation object has been previously initialized.
    To initialize the object the ``setKey()`` function has to be called with corresponding parameters after construction.
    
    :return: ``true`` if the object was initialized, ``false`` otherwise.

 .. java:method:: public PublicKey getPubKey()

    :return: returns the public key

BasicUsage
----------

We demonstrate a basic usage scenario with a sender party that wish to hide a secret using the trapdoor permutation,
and a receiver who is not able to invert the permutation on the secret.

Here is the code of the sender:

.. code-block:: java

    //Create public key, private key and secret
    ...
    
    //instantiate the trapdoor permutation:
    TrapdoorPermutation trapdoorPermutation = TrapdoorPermutationFactory.getInstance().getObject("RSA", "SCAPI");
    //set the keys for this trapdoor permutation
    trapdoorPermutation.setKey(publicKey, privateKey);
    
    // represent the secret (originally was of BigInteger type) using TPElement
    TPElement secretElement = trapdoorPermutation.generateTPElement(secret);
    //hide the secret using the trapdoor permutation
    TPElement maskedSecret = trapdoorPermutation.compute(secretElement);
    
    // this line will succeed, because the private key is known to the sender
    TPElement invertedElement = trapdoorPermutation.invert(maskedSecret);
    
    // send the public key and the secret to the other side
    channel.send(publicKey.getEncoded());
    channel.send(maskedSecret.generateSendableData());

Here is the code of the receiver:

.. code-block:: java

    Serializable pkey = channel.receive();
    TPElementSendableData secretMsg = (TPElementSendableData) channel.receive();
    
    // reconstruct publicKey from pkey
    ...
    
    //instantiate the trapdoor permutation:
    TrapdoorPermutation trapdoorPermutation = TrapdoorPermutationFactory.getInstance().getObject("RSA", "SCAPI");
    //set the keys for this trapdoor permutation
    trapdoorPermutation.setKey(publicKey);
    
    // reconstruct a TPElement from a TPElementSendableData
    TPElement maskedSecret = trapdoorPermutation.reconstructTPElement(secretMsg);
    
    // this line will fail, and throw KeyException, because the private key is not known to the receiver
    TPElement secretElement = trapdoorPermutation.invert(maskedSecret);

Supported Trapdoor Permutations
-------------------------------

In this section we present possible keys to the ``TrapdoorPermutationFactory``.

Scapi's own implementation of RSA trapdoor permutation:

==================   =============================================================
Key                  Class
==================   =============================================================
ScapiRSA             edu.biu.scapi.primitives.trapdoorPermutation.ScRSAPermutation
==================   =============================================================

Crypto++ implementation of RSA trapdoor permutation and Rabin trapdoor permutation:

=============   ==============================================================================
Key             Class
=============   ==============================================================================
CryptoPPRSA     edu.biu.scapi.primitives.trapdoorPermutation.cryptopp.CryptoPpRSAPermutation
CryptoPPRabin   edu.biu.scapi.primitives.trapdoorPermutation.cryptopp.CryptoPpRabinPermutation
=============   ==============================================================================
    
OpenSSL implementation of RSA trapdoor permutation:

=============   ==============================================================================
Key             Class
=============   ==============================================================================
OpenSSLRSA      edu.biu.scapi.primitives.trapdoorPermutation.openSSL.OpenSSLRSAPermutation
=============   ==============================================================================
