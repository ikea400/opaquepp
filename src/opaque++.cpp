#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include "opaque++.h"
#include "opaque-rust.h"

OpaqueServerSetup::OpaqueServerSetup() {
  const auto setup = opaque_create_server_setup();
  m_serverSetup.assign(setup.begin(), setup.end());
}

OpaqueServerSetup::OpaqueServerSetup(const std::span<const uint8_t> serverSetup)
    : m_serverSetup(serverSetup.begin(), serverSetup.end()) {}

std::vector<uint8_t> OpaqueServerSetup::getStaticPublicKey() const {
  const auto response = opaque_get_server_public_key(
      {m_serverSetup.data(), m_serverSetup.size()});
  std::vector<uint8_t> publicKey(response.begin(), response.end());
  return publicKey;
}

OpaqueCommon::OpaqueCommon(const std::string_view clientIdentifier,
                           const std::string_view serverIdentifier,
                           const std::string_view context)
    : m_clientIdentifier(clientIdentifier),
      m_serverIdentifier(serverIdentifier),
      m_context(context) {}

OpaqueServer::OpaqueServer(const OpaqueServerSetupPtr& serverSetup,
                           const std::string_view clientIdentifier,
                           const std::string_view serverIdentifier,
                           const std::string_view context)
    : OpaqueCommon(clientIdentifier, serverIdentifier, context),
      m_serverSetup(serverSetup) {}

std::vector<uint8_t> OpaqueServer::startRegistration(
    const std::span<const uint8_t> registrationRequest) {
  auto response = opaque_create_server_registration_response(
      OpaqueCreateServerRegistrationResponseParams{
          .server_setup = {m_serverSetup->get().data(),
                           m_serverSetup->get().size()},
          .user_identifier = m_clientIdentifier,
          .registration_request = {registrationRequest.data(),
                                   registrationRequest.size()},
      });

  std::vector<uint8_t> registrationResponse(
      response.registration_response.begin(),
      response.registration_response.end());

  return registrationResponse;
}

std::vector<uint8_t> OpaqueServer::startLogin(
    const std::string_view identifier,
    const std::span<const uint8_t> registrationRecord,
    const std::span<const uint8_t> loginRequest) {
  const auto response = opaque_start_server_login(OpaqueStartServerLoginParams{
      .server_setup = {m_serverSetup->get().data(),
                       m_serverSetup->get().size()},
      .registration_record = {registrationRecord.data(),
                              registrationRecord.size()},
      .start_login_request = {loginRequest.data(), loginRequest.size()},
      .user_identifier = {identifier.data(), identifier.size()},
      .context = m_context,
      .client_identifier = m_clientIdentifier,
      .server_identifier = m_serverIdentifier,
  });

  m_state.assign(response.server_login_state.begin(),
                 response.server_login_state.end());
  std::vector<uint8_t> loginResponse(response.login_response.begin(),
                                     response.login_response.end());
  return loginResponse;
}

void OpaqueServer::finishLogin(
    const std::span<const uint8_t> finishLoginRequest) {
  const auto response =
      opaque_finish_server_login(OpaqueFinishServerLoginParams{
          .server_login_state = {m_state.data(), m_state.size()},
          .finish_login_request = {finishLoginRequest.data(),
                                   finishLoginRequest.size()},
          .context = m_context,
          .client_identifier = m_clientIdentifier,
          .server_identifier = m_serverIdentifier});

  m_sessionKey.assign(response.session_key.begin(), response.session_key.end());
}

OpaqueClient::OpaqueClient(const std::string_view password,
                           const std::string_view clientIdentifier,
                           const std::string_view serverIdentifier,
                           const std::string_view context)
    : OpaqueCommon(clientIdentifier, serverIdentifier, context),
      m_password(password) {}

std::vector<uint8_t> OpaqueClient::startRegistration() {
  const auto response =
      opaque_start_client_registration(OpaqueStartClientRegistrationParams{
          .password = {reinterpret_cast<const std::uint8_t*>(m_password.data()),
                       m_password.size()},
      });

  m_state.assign(response.client_registration_state.begin(),
                 response.client_registration_state.end());

  return std::vector<uint8_t>(response.registration_request.begin(),
                              response.registration_request.end());
}

std::vector<uint8_t> OpaqueClient::finishRegistration(
    const std::span<const uint8_t> registrationResponse) {
  const auto response =
      opaque_finish_client_registration(OpaqueFinishClientRegistrationParams{
          .password = {reinterpret_cast<const std::uint8_t*>(m_password.data()),
                       m_password.size()},
          .registration_response = {registrationResponse.data(),
                                    registrationResponse.size()},
          .client_registration_state = {m_state.data(), m_state.size()},
          .client_identifier = m_clientIdentifier,
          .server_identifier = m_serverIdentifier,
          .key_stretching_config = KeyStretchingFunctionConfig{
              .variant = KeyStretchingFunctionVariant::RfcServerAuthentication,
          }});

  m_serverStaticPublicKey.assign(response.server_static_public_key.begin(),
                                 response.server_static_public_key.end());

  // Return the password file (registration record) that the server would store
  // for this user
  std::vector<uint8_t> registrationRecord(response.registration_record.begin(),
                                          response.registration_record.end());
  return registrationRecord;
}

std::vector<uint8_t> OpaqueClient::startLogin() {
  const auto response = opaque_start_client_login(OpaqueStartClientLoginParams{
      .password = {reinterpret_cast<const std::uint8_t*>(m_password.data()),
                   m_password.size()}});

  m_state.assign(response.client_login_state.begin(),
                 response.client_login_state.end());

  std::vector<uint8_t> loginRequest(response.start_login_request.begin(),
                                    response.start_login_request.end());

  return loginRequest;
}

std::vector<uint8_t> OpaqueClient::finishLogin(
    const std::span<const uint8_t> loginResponse) {
  const auto response =
      opaque_finish_client_login(OpaqueFinishClientLoginParams{
          .client_login_state = {m_state.data(), m_state.size()},
          .login_response = {loginResponse.data(), loginResponse.size()},
          .password = {reinterpret_cast<const std::uint8_t*>(m_password.data()),
                       m_password.size()},
          .client_identifier = m_clientIdentifier,
          .server_identifier = m_serverIdentifier,
          .context = m_context,
          .key_stretching_config = KeyStretchingFunctionConfig{
              .variant = KeyStretchingFunctionVariant::RfcServerAuthentication,
          }});

  if (!response.ok) {
    throw InvalidLoginException();
  }

  m_exportKey.assign(response.export_key.begin(), response.export_key.end());
  m_sessionKey.assign(response.session_key.begin(),
                      response.session_key.end());
  m_serverStaticPublicKey.assign(response.server_static_public_key.begin(),
                                 response.server_static_public_key.end());

  std::vector<uint8_t> loginRequest(response.finish_login_request.begin(),
                                    response.finish_login_request.end());

  return loginRequest;
}
