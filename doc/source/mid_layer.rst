Layer 2: Non Interactive Protocols
==================================

The second layer of Scapi includes different symmetric and asymmetric encryption schemes, message authentication codes and digital signatures. It heavily uses the primitives of the first layer to perform internal operations. For example, the ElGamal encryption scheme uses DlogGroup; CBC-MAC uses any of the PRPs defined in the first level.

.. toctree::
   :maxdepth: 2

   mid_layer/mac
   mid_layer/symmetric_enc
   mid_layer/asymmetric_enc
   mid_layer/digital_signatures
