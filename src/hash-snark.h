//
// Created by bakr on 02/12/22.
//

#ifndef LIBSNARK_TUTORIAL_HASH_SNARK_H
#define LIBSNARK_TUTORIAL_HASH_SNARK_H

#include <string>
#include "libsnark/relations/circuit_satisfaction_problems/tbcs/tbcs.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/tbcs_ppzksnark/tbcs_ppzksnark.hpp"
#include "libsnark/common/default_types/tbcs_ppzksnark_pp.hpp"

typedef libsnark::tbcs_ppzksnark_keypair<libsnark::default_tbcs_ppzksnark_pp> keypairT;
typedef libsnark::tbcs_ppzksnark_proving_key<libsnark::default_tbcs_ppzksnark_pp> provingKeyT;
typedef libsnark::tbcs_ppzksnark_verification_key<libsnark::default_tbcs_ppzksnark_pp> verificationKeyT;
typedef libsnark::tbcs_ppzksnark_proof<libsnark::default_tbcs_ppzksnark_pp> proofT;

class Hash_snark {
private:

    libsnark::tbcs_circuit zksnark_circuit;
    provingKeyT zksnark_proving_key;
    verificationKeyT zksnark_verifying_key;
    const std::string iv_AES = "EA09BF27D8A78555C3ABC7AF5EB01797";

    void init_zksnark_circuit();
public:

    Hash_snark();

    void generate_keys();

    // AB: A trusted party or the verifier can call this function
    void generate_key_pair();

    // This function should be called after `generate_key_pair` function is called
    provingKeyT get_proving_key()
    {
        return this->zksnark_proving_key;
    }

    // This function should be called after `generate_key_pair` function is called
    verificationKeyT get_verifying_key()
    {
        return this->zksnark_verifying_key;
    }

    // The prover encrypts the record using his encryption key, which is a secret
    std::string encrypt_record_AES(std::string& record, std::string& encryption_key);

    std::string decrypt_record_AES(std::string& encrypted_record, std::string& encryption_decryption_key);

    // This function takes any record (can be an encrypted record) and returns its hash
    std::string compute_hash(std::string& record);

    // The prover uses his proving key to create the proof out of the encrypted record
    proofT prove(std::string& enc_record, std::string& record_hash, std::string& encryption_decryption_key, provingKeyT& proving_key);

    // The verifier uses his verifying key to verify the proof provided against the encrypted record after computing its hash
    bool verify(std::string& enc_record, std::string& record_hash, verificationKeyT& verifying_key, proofT& proof);
};

#endif //LIBSNARK_TUTORIAL_HASH_SNARK_H
