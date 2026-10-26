#pragma once

#include <string>

namespace sm::alice {

    class Alice {
    public:
        Alice(std::string identity, std::string responder_identity,
            std::string long_term_key);

        void run(const std::string& kdc_host, const std::string& kdc_port,
                const std::string& bob_host, const std::string& bob_port) const;

    private:
        std::string identity_;
        std::string responder_identity_;
        std::string long_term_key_;
    };

}