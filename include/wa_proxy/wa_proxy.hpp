#pragma once
#include <eosio/eosio.hpp>
#include <eosio/fixed_bytes.hpp>
#include <eosio/asset.hpp>
#include <eosio/singleton.hpp>
#include <eosio/binary_extension.hpp>
#include <eosio/ignore.hpp>
#include <eosio/crypto.hpp>

#include "tables.hpp"

using namespace eosio;

namespace wa_proxy {

class [[eosio::contract]] waproxy_contract : public contract
{
public:
    using contract::contract;
    waproxy_contract(eosio::name receiver, eosio::name code, const datastream<const char*>& ds);
 
    /// @brief Proxy call. This action will use the signature and public key passed in to determine 
    /// if the caller is authorized to make this call. If every check passed, the contract will send the 
    /// relay_action as an inline action. The relay_action must only have the authorization of the user's 
    /// active permission.
    /// @param user The user to perform the relay_action. pubkey must be registered under the user.
    /// @param relay_action The action to be relayed. It must only have the authorization of the user's active permission.
    /// @param expiration The expiration time for the request. We need this to prevent replay attacks.
    /// @param pubkey The WA public key associated to the signature. pubkey must be registered under the user.
    /// @param sig The WA signature over (chain_id + relay_action + nonce + expiration).
    /// where chain_id is the Vaulta network chain_id, nonce is the user level nonce. 
    /// chain_id can be found in the config table and the nonce from the users table.
    [[eosio::action]] void proxycall(eosio::name user, const eosio::action& relay_action, block_timestamp expiration,
        const std::vector<char>& serialized_pubkey, const eosio::webauthn_signature& sig);

    [[eosio::action]] void regkey(eosio::name user, const std::vector<char>& serialized_pubkey, bool allow_android_origin);
    [[eosio::action]] void unregkey(eosio::name user, const std::vector<char>& serialized_pubkey);

    [[eosio::action]] void init(const std::string& chain_id, const std::string& rpid);

    [[eosio::action]] void regandroid(const std::string& andorid_origin_string, bool remove);
    [[eosio::action]] void freezeuser(eosio::name user, bool freeze);

private:
    void validate_user_state(eosio::name user);
    uint64_t get_and_increment_nonce(eosio::name user);
    void validate_public_key(const std::vector<char>& serialized_pubkey);
    const pubkeys& get_pubkey_info(eosio::name user, const std::vector<char>& serialized_pubkey);
    void validate_challenge(const eosio::action& relay_action, block_timestamp expiration, uint64_t nonce, const std::string& challenge);
    void validate_origin(const std::string& origin_string, const std::string& rpid, bool allow_android_origin);
    void validate_origin_domain(const std::string& url, const std::string& rpid);
    void validate_origin_android(const std::string& origin_string);
};

} // namespace wa_proxy
