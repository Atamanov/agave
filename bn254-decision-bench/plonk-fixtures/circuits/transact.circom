pragma circom 2.1.6;

include "poseidon.circom";

// Mirrors the zolana transact statement: one public input, a Poseidon hash
// chain over the per-input and per-output witness that the shielded pool
// commits to. Shape drives circuit size exactly as it does on the Groth16
// rails, so a PLONK proof of this circuit prices the same verifier work
// zolana's shapes would.
//
// One public signal, matching every zolana verifying key (nr_pubinputs = 1).
template Transact(nIn, nOut) {
    signal output statementHash;         // the single public signal
    signal input nullifiers[nIn];        // private
    signal input utxoRoots[nIn];
    signal input outputOwners[nOut];
    signal input outputAmounts[nOut];

    // Fold the witness into a hash chain, then bind it to the public signal.
    component chain[nIn + nOut];
    signal acc[nIn + nOut + 1];
    acc[0] <== 0;

    for (var i = 0; i < nIn; i++) {
        chain[i] = Poseidon(3);
        chain[i].inputs[0] <== acc[i];
        chain[i].inputs[1] <== nullifiers[i];
        chain[i].inputs[2] <== utxoRoots[i];
        acc[i + 1] <== chain[i].out;
    }
    for (var j = 0; j < nOut; j++) {
        chain[nIn + j] = Poseidon(3);
        chain[nIn + j].inputs[0] <== acc[nIn + j];
        chain[nIn + j].inputs[1] <== outputOwners[j];
        chain[nIn + j].inputs[2] <== outputAmounts[j];
        acc[nIn + j + 1] <== chain[nIn + j].out;
    }

    statementHash <== acc[nIn + nOut];
}
