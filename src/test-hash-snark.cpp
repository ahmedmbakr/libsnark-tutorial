#include "hash-snark.h"
#include "iostream"

struct Zksnark_public_info
{
    std::string enc_record;
    std::string record_hash_256;
}zksnark_public_info;

proofT execute_prover(Hash_snark& hash_snark)
{
    std::string secret_record = "It is ahmed bakr plain text. It is also a very secret text.";
    std::string encryption_key = "72E0653BBAF257E65EA909955AE9A2A6";
    std::string encrypted_record = hash_snark.encrypt_record_AES(secret_record, encryption_key);

    // For testing only to make sure that the decryption result in the original text
    //std::string original_decrypted_record = hash_snark.decrypt_record_AES(encrypted_record, encryption_key);

    auto record_hash = hash_snark.compute_hash(secret_record);
    std::cout << "Record Hash: " << record_hash << std::endl;

    // Prover sets public info. This should be a serialized data saved somewhere in P2P network
    zksnark_public_info.enc_record = encrypted_record;
    zksnark_public_info.record_hash_256 = record_hash;

    auto prover_key = hash_snark.get_proving_key();
    auto proof = hash_snark.prove(encrypted_record, record_hash, encryption_key, prover_key);
    std::cout << "Prover finished execution" << std::endl;
    return proof;
}

bool execute_verifier(Hash_snark& hash_snark, proofT& proof)
{
    auto verify_key = hash_snark.get_verifying_key();
    bool is_verified = hash_snark.verify(zksnark_public_info.enc_record, zksnark_public_info.record_hash_256, verify_key, proof);
    return is_verified;
}

int main()
{
    std::cout << "Test Hash Snark" << std::endl;
    Hash_snark hash_snark;
    hash_snark.generate_keys();

    auto proof = execute_prover(hash_snark);
    bool verification_result = execute_verifier(hash_snark, proof);
    std::cout << "Verification output: " << verification_result << std::endl;
}

