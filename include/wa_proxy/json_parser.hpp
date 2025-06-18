#pragma once

#include <rapidjson/reader.h>
#include <rapidjson/error/en.h>

namespace wa_proxy {

struct ClientDataJsonHandler
    : public rapidjson::BaseReaderHandler<rapidjson::UTF8<>, ClientDataJsonHandler> {

    typedef enum {
        kStateExpectOrigin,
        kStateExpectChallenge,
        kStateExpectType,
        kStateIgnore
    } ClientDataJsonParserState;
    
    ClientDataJsonHandler() : m_state(ClientDataJsonParserState::kStateIgnore) {}

    bool Default() { 
        // Ignore all other inputs.
        return true; 
    }
    
    bool String(const char* str, rapidjson::SizeType length, bool /*copy*/) { 
        switch (m_state)
        {
        case ClientDataJsonParserState::kStateExpectOrigin:
            origin = std::string(str,length);
            break;
        case ClientDataJsonParserState::kStateExpectChallenge:
            challenge = std::string(str,length);
            break;
        case ClientDataJsonParserState::kStateExpectType:
            type = std::string(str,length);
            break;
        default:
            break;
        }
        m_state = ClientDataJsonParserState::kStateIgnore;
        return true;
    }

    bool Key(const char* str, rapidjson::SizeType length, bool copy) {
        if (0 == strncmp(str, "origin", length)) {
            m_state = ClientDataJsonParserState::kStateExpectOrigin;
        }
        else if (0 == strncmp(str, "challenge", length)) {
            m_state = ClientDataJsonParserState::kStateExpectChallenge;
        }
        else if (0 == strncmp(str, "type", length)) {
            m_state = ClientDataJsonParserState::kStateExpectType;
        }
        else {
            // We don't care about the reset fields for now.
            m_state = ClientDataJsonParserState::kStateIgnore;
        }
        return true;
    }

    ClientDataJsonParserState m_state;
    std::string origin;
    std::string challenge;
    std::string type;
    
};

using ParsedClientData = ClientDataJsonHandler;

ParsedClientData parse_client_data_json(const std::string& json) {
    ClientDataJsonHandler jsonParserHandler;
    rapidjson::Reader jsonReader;
    rapidjson::StringStream ss(json.c_str());
    jsonReader.Parse(ss, jsonParserHandler);
    return jsonParserHandler;
}

} // namespace wa_proxy
