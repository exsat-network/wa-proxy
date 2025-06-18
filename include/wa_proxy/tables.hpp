#pragma once
#include <eosio/eosio.hpp>
#include <eosio/fixed_bytes.hpp>
#include <eosio/singleton.hpp>
#include <eosio/binary_extension.hpp>
#include <eosio/crypto.hpp>


namespace wa_proxy {

// Avoid using the whole namespace.
using eosio::multi_index;
using eosio::checksum256;
using eosio::name;
using eosio::sha256;
using eosio::const_mem_fun;
using eosio::indexed_by;

struct [[eosio::table]] [[eosio::contract("waproxy_contract")]] pubkeys {
   
    uint64_t    id;
    name       user;
    std::vector<char>       pubkey;
    bool allow_android_origin;

    uint64_t primary_key()const { return id; }

    checksum256 by_pubkey()const { 
        return sha256(pubkey.data(), pubkey.size());
    }

    uint64_t by_user()const { 
        return user.value;
    }

    EOSLIB_SERIALIZE(pubkeys, (id)(user)(pubkey)(allow_android_origin));
};

typedef multi_index< "pubkeys"_n, pubkeys,
    indexed_by<"by.pubkey"_n, const_mem_fun<pubkeys, checksum256, &pubkeys::by_pubkey>>,
    indexed_by<"by.user"_n, const_mem_fun<pubkeys, uint64_t, &pubkeys::by_user>>
> pubkeys_table;

struct [[eosio::table]] [[eosio::contract("waproxy_contract")]] users {
   
    name       user;
    uint64_t   nonce;
    bool       freeze;

    uint64_t primary_key()const { return user.value; }

    EOSLIB_SERIALIZE(users, (user)(nonce)(freeze));
};

typedef multi_index< "users"_n, users> users_table;

struct [[eosio::table]] [[eosio::contract("waproxy_contract")]] android_origins {
   
    uint64_t   id;
    std::string android_origin;

    uint64_t primary_key()const { return id; }

    checksum256 by_android_origin()const { 
        return sha256(android_origin.data(), android_origin.size());
    }

    EOSLIB_SERIALIZE(android_origins, (id)(android_origin));
};

typedef multi_index< "androidorgin"_n, android_origins,
    indexed_by<"by.android"_n, const_mem_fun<android_origins, checksum256, &android_origins::by_android_origin>>
> android_origins_table;

struct [[eosio::table]] [[eosio::contract("waproxy_contract")]] config {
    uint64_t id;
    std::string       rpid;
    std::string       chain_id;

    uint64_t primary_key()const { return id; }
    EOSLIB_SERIALIZE(config, (id)(rpid)(chain_id));
};

typedef multi_index< "config"_n, config> config_table;

} // namespace wa_proxy
