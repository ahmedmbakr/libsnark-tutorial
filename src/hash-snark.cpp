//
// Created by bakr on 02/12/22.
//

#include <armadillo>
#include "hash-snark.h"
#include "libsnark/gadgetlib1/gadget.hpp"
#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/tbcs_ppzksnark/tbcs_ppzksnark.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/common/default_types/tbcs_ppzksnark_pp.hpp"

#include <cryptopp/rijndael.h>
#include <cryptopp/aes.h>
#include "cryptopp/cryptlib.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"

using namespace libsnark;
using namespace CryptoPP;

typedef libff::Fr<default_tbcs_ppzksnark_pp> FieldT;

Hash_snark::Hash_snark() {
    this->init_zksnark_circuit();
}

void Hash_snark::init_zksnark_circuit() {
    // Circuit building is based on this blog: https://blog.statebox.org/boolean-circuits-in-libsnark-facf7c23400b

    // Initialize public parameters
    default_tbcs_ppzksnark_pp::init_public_params();

    // Initialize the circuit
    this->zksnark_circuit.primary_input_size = 0;     // number of PUBLIC inputs
    this->zksnark_circuit.auxiliary_input_size = 3;   // number of PRIVATE inputs

    tbcs_gate gate;
    gate.left_wire = 1; // The gate has an input with the ID 1
    gate.right_wire = 2;// The gate has an input with the ID 2
    gate.type = tbcs_gate_type(14);     // NAND (The final circuit output has to be zero so that it is satisfied)
    gate.output = 4; // The output of the gate has the ID 4
    gate.is_circuit_output = true;

    this->zksnark_circuit.add_gate(gate);// Add the gate to zksnark circuit
}

void Hash_snark::generate_keys()
{
    // Create trusted setup and generate keys
    const keypairT zksnark_keypair = tbcs_ppzksnark_generator<default_tbcs_ppzksnark_pp>(this->zksnark_circuit);
    this->zksnark_proving_key = zksnark_keypair.pk;
    this->zksnark_verifying_key = zksnark_keypair.vk;
}

std::string
Hash_snark::encrypt_record_AES(std::string &record, std::string &encryption_key) {
    AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(std::cout));
    std::string cipherHex;
    HexEncoder encoderToString(new StringSink(cipherHex));

    std::cout << "plain text: " << record << std::endl;

//    SecByteBlock key(AES::MIN_KEYLENGTH);
    std::string iv_str = this->iv_AES;
    SecByteBlock key((const byte *)&encryption_key[0], encryption_key.size());
    SecByteBlock iv((const byte *)&iv_str[0], iv_str.size());
    std::string cipher, recovered;
    try
    {
        CBC_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        StringSource s(record, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)
                       ) // StreamTransformationFilter
        ); // StringSource
    }
    catch(const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    std::cout << "cipher text: ";
    encoder.Put((const byte*)&cipher[0], cipher.size());
    encoder.MessageEnd();
    encoderToString.Put((const byte*)&cipher[0], cipher.size());
    encoderToString.MessageEnd();
    std::cout << std::endl;

    return cipher;
}

std::string Hash_snark::compute_hash(std::string &record) {
    SHA256 hash;
    std::string digest;

    StringSource s(record, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    return digest;
}

std::string Hash_snark::decrypt_record_AES(std::string &encrypted_record, std::string &encryption_decryption_key) {
    std::string iv_str = this->iv_AES;
    SecByteBlock key((const byte *)&encryption_decryption_key[0], encryption_decryption_key.size());
    SecByteBlock iv((const byte *)&iv_str[0], iv_str.size());

    std::string recovered;

    try
    {
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        StringSource s(encrypted_record, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)
                       ) // StreamTransformationFilter
        ); // StringSource

        std::cout << "recovered text: " << recovered << std::endl;
    }
    catch(const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    return recovered;
}

proofT Hash_snark::prove(std::string &enc_record, std::string& record_hash, std::string& encryption_decryption_key, provingKeyT& proving_key) {

    auto decrypted_record = this->decrypt_record_AES(enc_record, encryption_decryption_key);
    bool ret_value = record_hash == this->compute_hash(decrypted_record);
    std::vector<bool> secret_vector = {1,ret_value,0};

    // public input is empty
    tbcs_primary_input pi = {};
    // private input
    tbcs_auxiliary_input ai = secret_vector;

    proofT proof = tbcs_ppzksnark_prover<default_tbcs_ppzksnark_pp>(proving_key, pi, ai);
    return proof;
}

bool Hash_snark::verify(std::string &enc_record, std::string &record_hash,
                        verificationKeyT& verifying_key, proofT& proof) {
    // public input is empty
    tbcs_primary_input pi = {};
    bool verified = tbcs_ppzksnark_verifier_strong_IC<default_tbcs_ppzksnark_pp>
            (verifying_key, pi, proof);
    return verified;
}
