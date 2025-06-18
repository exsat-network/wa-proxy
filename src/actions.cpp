
#include <eosio/system.hpp>
#include <eosio/transaction.hpp>
#include <eosio/base64.hpp>
#include <eosio/crypto.hpp>
#include <eosio/datastream.hpp>

#include <wa_proxy/wa_proxy.hpp>
#include <wa_proxy/json_parser.hpp>

using namespace eosio;

namespace wa_proxy {

void waproxy_contract::validate_user_state(eosio::name user) {
    users_table users_table_v(get_self(), get_self().value);
    auto user_iter = users_table_v.find(user.value);
    if (user_iter == users_table_v.end()) {
        users_table_v.emplace(get_self(), [&](users& a) {
            a.user = user;
            a.nonce = 0;
            a.freeze = false;
        });
    }

    user_iter = users_table_v.find(user.value);
    eosio::check(!user_iter->freeze, "User blocked.");
}

uint64_t waproxy_contract::get_and_increment_nonce(eosio::name user) {
    users_table users_table_v(get_self(), get_self().value);
    auto user_iter = users_table_v.find(user.value);
    eosio::check(user_iter != users_table_v.end(), "User not initialized.");
    uint64_t nonce = user_iter->nonce;
    users_table_v.modify(*user_iter, eosio::same_payer, [](users& a){
        ++a.nonce;
    });
    return nonce;
}

void waproxy_contract::validate_public_key(const std::vector<char>& serialized_pubkey) {
    const auto pubkey = unpack<eosio::webauthn_public_key>(serialized_pubkey);
    const std::string& rpid = pubkey.rpid;
    config_table config_table_v(get_self(), get_self().value);
    auto config_iter = config_table_v.begin();
    eosio::check(config_iter != config_table_v.end(), "contract not initialized");
    if (rpid == "localhost") {
        // Temporary setting for debug
        // TODO: remove it before launch
        return;
    }
    eosio::check(config_iter->rpid == rpid, "requested rpid does not match saved rpid");
}

const pubkeys& waproxy_contract::get_pubkey_info(eosio::name user, const std::vector<char>& serialized_pubkey) {
    pubkeys_table pubkey_table_v(get_self(), get_self().value);
    auto pubkey_inx = pubkey_table_v.get_index<"by.pubkey"_n>();
    auto pubkey_iter = pubkey_inx.find(sha256(serialized_pubkey.data(), serialized_pubkey.size()));

    eosio::check(pubkey_iter != pubkey_inx.end() && pubkey_iter->user == user, 
        "Public key not registered for the requested user");

    // Maybe not safe if we erase the row after got this, buf it should be fine for current usages.
    return *pubkey_iter;
}

void waproxy_contract::validate_challenge(const eosio::action& relay_action, block_timestamp expiration, uint64_t nonce, const std::string& challenge) {
    // challenge = hash(chain_id + action + nonce + expire)
    // challenge string should be base64Url encoded.
    config_table config_table_v(get_self(), get_self().value);
    auto config_iter = config_table_v.begin();

    std::vector<char> serialize;
    serialize.resize(pack_size(config_iter->chain_id) + pack_size(relay_action) + 
                        pack_size(nonce) + pack_size(expiration));

    datastream<char*> ds( serialize.data(), serialize.size() );
    ds << config_iter->chain_id;
    ds << relay_action;
    ds << nonce;
    ds << expiration;

    const auto digest_challenge_data = sha256(serialize.data(), serialize.size()).extract_as_byte_array();
    const auto challenge_str = base64url_encode(std::string_view{(const char*)digest_challenge_data.data(), 32});
    eosio::check(challenge_str == challenge, "Signature challenge check failed.");
}

void waproxy_contract::validate_origin(const std::string& origin_string, const std::string& rpid, bool allow_android_origin) {
    // Check origin
    if (origin_string.starts_with("https://")) {
        validate_origin_domain(rpid, origin_string);
    }
    else if (origin_string.starts_with("android:")) {
        eosio::check(allow_android_origin, "Android access for this key is not enabled.");
        validate_origin_android(origin_string);
    }
    else {
        // Unsupported Scheme
        eosio::check(false, "Unsupported scheme in origin");
    }
}

void waproxy_contract::validate_origin_domain(const std::string& url, const std::string& rpid) {
    // Follow the exact match rule for now.
    // Note that we use the rfind to search for the separator for the port.
    // nops will be return if not found.
    // But this will be fine as substr can tolerate a large len and just return the rest of the string.
    // strlen("https://") = 8;
    eosio::check(rpid == url.substr(0, url.rfind(':') - 8), "origin failed to match rpid");
}

void waproxy_contract::validate_origin_android(const std::string& origin_string) {
    android_origins_table androids(get_self(), get_self().value);
    auto inx = androids.get_index<"by.android"_n>();
    auto itr = inx.find(sha256(origin_string.data(), origin_string.size()));
    eosio::check(itr != inx.end(), "Unsupported android app");
}

// Ctor
waproxy_contract::waproxy_contract(eosio::name receiver, eosio::name code, const datastream<const char*>& ds) : 
    contract(receiver, code, ds) {           
}

// Actions
void waproxy_contract::init(const std::string& chain_id, const std::string& rpid) {
    require_auth(get_self());

    config_table config_table_v(get_self(), get_self().value);
    auto config_iter = config_table_v.begin();
    eosio::check(config_iter == config_table_v.end(), "contract already initialized");

    config_table_v.emplace(get_self(), [&](config& a) {
        a.id = 0;
        a.chain_id = chain_id;
        a.rpid = rpid;
    });
}

void waproxy_contract::regandroid(const std::string& andorid_origin_string, bool remove) {
    require_auth(get_self());

    android_origins_table androids(get_self(), get_self().value);
    auto inx = androids.get_index<"by.android"_n>();
    auto itr = inx.find(sha256(andorid_origin_string.data(), andorid_origin_string.size()));
    if (itr == inx.end() && !remove) {
        androids.emplace(get_self(), [&](android_origins& a) {
            a.id = androids.available_primary_key();
            a.android_origin = andorid_origin_string;
        });
    }
    else if (itr != inx.end() && remove) {
        androids.erase(*itr);
    }
}

void waproxy_contract::freezeuser(eosio::name user, bool freeze) {
    require_auth(get_self());

    users_table users_table_v(get_self(), get_self().value);
    auto user_iter = users_table_v.find(user.value);
    eosio::check(user_iter != users_table_v.end(), "User not initialized.");
    users_table_v.modify(*user_iter, eosio::same_payer, [&](users& a){
        a.freeze = freeze;
    });
}

void waproxy_contract::unregkey(eosio::name user, const std::vector<char>& serialized_pubkey) {
    require_auth(user);

    validate_user_state(user);
    validate_public_key(serialized_pubkey);
    const auto& entry = get_pubkey_info(user, serialized_pubkey);

    // existence checked above 
    pubkeys_table pubkey_table_v(get_self(), get_self().value);
    pubkey_table_v.erase(entry);
}

void waproxy_contract::regkey(eosio::name user, const std::vector<char>& serialized_pubkey, bool allow_android_origin) {
    require_auth(user);

    validate_user_state(user);
    validate_public_key(serialized_pubkey);

    pubkeys_table pubkey_table_v(get_self(), get_self().value);
    auto pubkey_inx = pubkey_table_v.get_index<"by.pubkey"_n>();
    auto pubkey_iter = pubkey_inx.find(sha256(serialized_pubkey.data(), serialized_pubkey.size()));

    if (pubkey_iter == pubkey_inx.end()) {
        pubkey_table_v.emplace(get_self(), [&](pubkeys& a) {
            a.user = user;
            a.id = pubkey_table_v.available_primary_key();
            a.allow_android_origin = allow_android_origin;
            a.pubkey = serialized_pubkey;
        });
    }
    else {
        eosio::check(pubkey_iter->user == user, "Public key not registered for the requested user");
        if (pubkey_iter->allow_android_origin != allow_android_origin) {
            pubkey_table_v.modify(*pubkey_iter, eosio::same_payer, [&](pubkeys& a){
                a.allow_android_origin = allow_android_origin;
            });
        }
    } 
}

void waproxy_contract::proxycall(eosio::name user, const eosio::action& relay_action, block_timestamp expiration,
    const std::vector<char>& serialized_pubkey, const eosio::webauthn_signature& sig) {

    // Sanity Checks for Requested Action
    // We check them first as such mistakes could be common and the checks are cheaper.
    
    // Check expiration time
    const block_timestamp current_time = current_block_time();
    eosio::check(expiration >= current_time, "request expired");

    // Checks to action permission levels
    eosio::check( relay_action.authorization.size() == 1 && 
        relay_action.authorization[0] == permission_level(user, "active"_n), 
        "Relay actions can only have the user's active authorization.");

    // Validate user states and key ownership

    // Validate user state
    validate_user_state(user);
    // Validate requested public key is registered for the user
    validate_public_key(serialized_pubkey);
    const auto& pubkey_entry = get_pubkey_info(user, serialized_pubkey);

    // Load some info for future use.
    bool allow_android_origin = pubkey_entry.allow_android_origin;
    // Use the rpid in public key is it is already validated.
    const auto pubkey = unpack<eosio::webauthn_public_key>(serialized_pubkey);
    const std::string& rpid = pubkey.rpid;
    const std::vector<uint8_t>& auth_data = sig.auth_data;
    const std::string& client_data_json = sig.client_json;

    // Verify the WA Signature

    // Validate auth_data
    constexpr static size_t min_auth_data_size = 37;
    eosio::check(auth_data.size() >= min_auth_data_size, "auth_data not as large as required");

    webauthn_public_key::user_presence_t user_presence;
    if(auth_data[32] & 0x01)
        user_presence = webauthn_public_key::user_presence_t::USER_PRESENCE_PRESENT;
    if(auth_data[32] & 0x04)
        user_presence = webauthn_public_key::user_presence_t::USER_PRESENCE_VERIFIED;
    eosio::check(pubkey.user_presence == user_presence, "expected user_presence not match");

    // Validate rpid hash
    const auto hash_rpid = sha256(rpid.data(), rpid.size()).extract_as_byte_array();
    eosio::check(0 == memcmp(hash_rpid.data(), auth_data.data(), 32), "Signature rpid check failed.");
    
    // Validate client data
    // Parse client data
    ParsedClientData parsed_client_data = parse_client_data_json(client_data_json);
    
    // Validate type
    eosio::check(parsed_client_data.type == "webauthn.get", "webauthn signature type not an assertion");

    // Validate origin
    validate_origin(parsed_client_data.origin, rpid, allow_android_origin);

    // Validate challenge
    const uint64_t nonce = get_and_increment_nonce(user);
    validate_challenge(relay_action, expiration, nonce, parsed_client_data.challenge);

    // Validate ECC Signature
    // signed_data = auth_data + hash(client_json)
    std::vector<char> signed_data = std::vector<char>(auth_data.begin(), auth_data.end());
    const auto digest_client_data = sha256(client_data_json.data(), client_data_json.size()).extract_as_byte_array();
    signed_data.insert(signed_data.end(), digest_client_data.data(), digest_client_data.data() + 32);
    
    const checksum256 digest_to_verify = sha256(signed_data.data(), signed_data.size());
    
    signature sig_to_verify;
    sig_to_verify.emplace<1>(sig.compact_signature); // 1 = R1 Curve

    public_key pubkey_to_verify;
    pubkey_to_verify.emplace<1>(pubkey.key); // 1 = R1 Curve

    assert_recover_key(digest_to_verify, sig_to_verify, pubkey_to_verify);

    // All checks passed!

    // Relay Action
    relay_action.send();

    // Nonce already changed.
}

} // namespace wa_proxy
