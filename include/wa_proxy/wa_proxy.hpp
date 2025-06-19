#pragma once
#include <eosio/eosio.hpp>
#include <eosio/fixed_bytes.hpp>
#include <eosio/asset.hpp>
#include <eosio/singleton.hpp>
#include <eosio/binary_extension.hpp>
#include <eosio/ignore.hpp>
#include <eosio/crypto.hpp>


namespace wa_proxy {

struct pubkeys; // forward declaration for table entry.

class [[eosio::contract]] waproxy_contract : public eosio::contract
{
public:
    using contract::contract;
    waproxy_contract(eosio::name receiver, eosio::name code, const eosio::datastream<const char*>& ds);
 
    /**
     * @brief Proxy call. 
     * This action will use the signature and public key passed in to determine if the caller is authorized to make this call.
     * If every check passed, the contract will send the relay_action as an inline action. 
     * The relay_action must only have the authorization of the user's active permission.
     * 
     * @auth None. This action relies on the signature to determine the authorization.
     * 
     * @param user The user to perform the relay_action. pubkey must be registered under the user.
     * @param relay_actions The actions to be relayed. They must only have the authorization of the user's active permission.
     * Zero length action array can be used to cancel requests that are not finalized by consuming the nonce.
     * @param expiration The expiration time for the request. We need this to prevent replay attacks.
     * @param serialized_pubkey The serialized WA public key associated to the signature. pubkey must be registered under the user.
     * @param serialized_sig The serialized WA signature over (chain_id + relay_action + nonce + expiration).
     * where chain_id is the Vaulta network chain_id, nonce is the user level nonce. 
     * chain_id can be found in the config table and the nonce from the users table.
     */
    [[eosio::action]] void proxycall(eosio::name user, const std::vector<eosio::action>& relay_actions, eosio::block_timestamp expiration,
        const std::vector<char>& serialized_pubkey, const std::vector<char>& serialized_sig);

    /**
     * @brief Register a public key for the user. 
     * If called on a registered key, update the android origin flag.
     * The action will fail if the key has already been registered to another user.
     * 
     * @auth user
     * 
     * @param user The user to registered the key to. 
     * @param serialized_pubkey The serialized WA public key to register.
     * @param allow_android_origin Set a flag to indicate whether this key is allowed for requests from android apps.
     */
    [[eosio::action]] void regkey(eosio::name user, const std::vector<char>& serialized_pubkey, bool allow_android_origin);
    
    /**
     * @brief Unregister a public key.
     * The action will fail if the key is registered to another user.
     * 
     * @auth user
     * 
     * @param user The user to unregistered the key from.
     * @param serialized_pubkey The serialized WA public key to unregister.
     */
    [[eosio::action]] void unregkey(eosio::name user, const std::vector<char>& serialized_pubkey);

    /**
     * @brief Initialize the contract.
     * 
     * @auth self
     * 
     * @param chain_id The chain_id of the network in string.
     * @param rpid The rpid in string.
     */
    [[eosio::action]] void init(const eosio::checksum256& chain_id, const std::string& rpid);

    /**
     * @brief Register or unregister an android origin string.
     * 
     * @auth self
     * 
     * @param andorid_origin_string The android origin string to register or unregister.
     * @param remove Remove flag. If this flag is set, unregister the target android origin string.
     */
    [[eosio::action]] void regandroid(const std::string& andorid_origin_string, bool remove);

    /**
     * @brief Freeze or unfreeze an user.
     * 
     * @auth self
     * 
     * @param user The user to freeze or unfreeze
     * @param freeze Freeze flag. The user's freeze state will be set to this flag.
     */
    [[eosio::action]] void freezeuser(eosio::name user, bool freeze);

private:
    void validate_user_state(eosio::name user);
    uint64_t get_and_increment_nonce(eosio::name user);
    
    void validate_public_key(const std::vector<char>& serialized_pubkey);
    const pubkeys& get_pubkey_info(eosio::name user, const std::vector<char>& serialized_pubkey);
    
    void validate_challenge(const std::vector<eosio::action>& relay_actions, eosio::block_timestamp expiration, uint64_t nonce, const std::string& challenge);
    
    void validate_origin(const std::string& origin_string, const std::string& rpid, bool allow_android_origin);
    void validate_origin_domain(const std::string& origin_string, const std::string& rpid);
    void validate_origin_android(const std::string& origin_string);
};

} // namespace wa_proxy
