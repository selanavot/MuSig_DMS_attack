# Attack Against MuSig with Delayed Message Selection

This is a Sage implementation of the attack against MuSig when used insecurely with delayed message selection, presented in [Eprint 2024/437](https://eprint.iacr.org/2024/437).

We present the attack against our toy implementation of MuSig, that can be found in `musig.sage`, implemented over SHA256 and our toy implementation of the [secp256k1 curve](https://en.bitcoin.it/wiki/Secp256k1).

**Requirements:** To try it out, you must first install [SageMath](https://www.sagemath.org/).

**The attack:** This attack is implemented in the two signers setting (though it can easily be generalized for more). The adversary first queries a signing oracle for signature on the following honest messages:
* "very normal message."
* "another very normal message."

Then, the adversary forges a signature for the following massage:
* "message that no signer is willing to sign under any circumstances"


**Trying it out:** To run the attack, simply run the adversary code (`sage adversary.sage`), which prints out a forged signature. It should not take more than a few seconds. The rest of the files do the following:

* `musig.sage` provides our toy implementation of the insecure version of MuSig, using parameters defined in `params.sage`.
* `signing_test.sage` checks the correctness of the scheme by generating a valid signature and verifying it.
* `unforgeability_game.sage` provides the signing oracles that the adversary uses.

**Disclaimer:** This is a simplest working example of the attack, and our broken toy scheme is designed to be as simple as possible. Therefore, it likely has implementation based security vulnerabilities, unrelated to the attack.