#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct InvalidLoginException : public std::exception {
  const char* what() const noexcept override { return "Login failed"; }
};

class OpaqueServerSetup {
 public:
  explicit OpaqueServerSetup();
  explicit OpaqueServerSetup(const std::span<const uint8_t> serverSetup);

  std::vector<uint8_t> getStaticPublicKey() const;

  const std::vector<uint8_t>& get() { return m_serverSetup; }

 private:
  std::vector<uint8_t> m_serverSetup;
};

using OpaqueServerSetupPtr = std::shared_ptr<OpaqueServerSetup>;

class OpaqueCommon {
 public:
  OpaqueCommon(const std::string_view clientIdentifier,
               const std::string_view serverIdentifier,
               const std::string_view context);

  std::span<const uint8_t> getSessionKey() const { return m_sessionKey; }

 protected:
  std::string m_clientIdentifier;
  std::string m_serverIdentifier;
  std::string m_context;

  std::vector<uint8_t> m_state;
  std::vector<uint8_t> m_sessionKey;
};

class OpaqueServer : public OpaqueCommon {
 public:
  explicit OpaqueServer(const OpaqueServerSetupPtr& serverSetup,
                        const std::string_view clientIdentifier,
                        const std::string_view serverIdentifier,
                        const std::string_view context);

  std::vector<uint8_t> startRegistration(
      const std::span<const uint8_t> registrationRequest);

  std::vector<uint8_t> startLogin(
      const std::string_view identifier,
      const std::span<const uint8_t> registrationRecord,
      const std::span<const uint8_t> loginRequest);

  void finishLogin(const std::span<const uint8_t> finishLoginRequest);

 private:
  std::shared_ptr<OpaqueServerSetup> m_serverSetup;
};

class OpaqueClient : public OpaqueCommon {
 public:
  explicit OpaqueClient(const std::string_view password,
                        const std::string_view clientIdentifier,
                        const std::string_view serverIdentifier,
                        const std::string_view context);

  std::vector<uint8_t> startRegistration();
  std::vector<uint8_t> finishRegistration(
      const std::span<const uint8_t> registrationResponse);

  std::vector<uint8_t> startLogin();
  std::vector<uint8_t> finishLogin(
      const std::span<const uint8_t> loginResponse);

  std::span<const uint8_t> getServerStaticPublicKey() const {
    return m_serverStaticPublicKey;
  }

  std::span<const uint8_t> getExportKey() const { return m_exportKey; }

 private:
  std::string m_password;
  std::vector<uint8_t> m_serverStaticPublicKey;
  std::vector<uint8_t> m_exportKey;
};