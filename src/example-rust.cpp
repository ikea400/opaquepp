#include <chrono>
#include <cstdint>
#include <exception>
#include <ios>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "opaque-rust.h"

static void print_hex(const std::span<const std::uint8_t> data) {
  for (const auto& byte : data) {
    std::cout << std::hex << static_cast<int>(byte) << " ";
  }
  std::cout << std::dec << "\n";  // Reset to decimal
}

static auto account_registration(
    const std::span<const std::uint8_t> server_setup,
    const std::string_view password, const std::string& client_identifier,
    const std::string& server_identifier) {
  auto start_client_registration =
      opaque_start_client_registration(OpaqueStartClientRegistrationParams{
          .password = {reinterpret_cast<const std::uint8_t*>(password.data()),
                       password.size()},
      });

  // Client sends client_registration.registration_request to server

  auto create_server_registration = opaque_create_server_registration_response(
      OpaqueCreateServerRegistrationResponseParams{
          .server_setup = {server_setup.data(), server_setup.size()},
          .user_identifier = client_identifier,
          .registration_request =
              {start_client_registration.registration_request.data(),
               start_client_registration.registration_request.size()},
      });

  // Server sends create_server_registration.registration_response to client

  auto finish_client_registration =
      opaque_finish_client_registration(OpaqueFinishClientRegistrationParams{
          .password = {reinterpret_cast<const std::uint8_t*>(password.data()),
                       password.size()},
          .registration_response =
              {create_server_registration.registration_response.data(),
               create_server_registration.registration_response.size()},
          .client_registration_state =
              {start_client_registration.client_registration_state.data(),
               start_client_registration.client_registration_state.size()},
          .client_identifier = client_identifier,
          .server_identifier = server_identifier,
          .key_stretching_config = KeyStretchingFunctionConfig{
              .variant = KeyStretchingFunctionVariant::RfcServerAuthentication,
          }});

  // Client sends finish_client_registration.registration_record to server

  return finish_client_registration.registration_record;
}

static auto account_login(
    const std::span<const std::uint8_t> server_setup,
    const std::string_view password, const std::string& client_identifier,
    const std::string& server_identifier, const std::string& context,
    const std::span<const std::uint8_t> registration_record) {
  const auto start_client_login =
      opaque_start_client_login(OpaqueStartClientLoginParams{
          .password = {reinterpret_cast<const std::uint8_t*>(password.data()),
                       password.size()}});

  // Client sends start_client_login.start_login_request to server
  const auto start_server_login =
      opaque_start_server_login(OpaqueStartServerLoginParams{
          .server_setup = {server_setup.data(), server_setup.size()},
          .registration_record = {registration_record.data(),
                                  registration_record.size()},
          .start_login_request =
              {start_client_login.start_login_request.data(),
               start_client_login.start_login_request.size()},
          .user_identifier = client_identifier,
          .context = context,
          .client_identifier = client_identifier,
          .server_identifier = server_identifier,
      });

  // Server sends start_server_login.login_response to client

  const auto finish_client_login =
      opaque_finish_client_login(OpaqueFinishClientLoginParams{
          .client_login_state = {start_client_login.client_login_state.data(),
                                 start_client_login.client_login_state.size()},
          .login_response = {start_server_login.login_response.data(),
                             start_server_login.login_response.size()},
          .password = {reinterpret_cast<const std::uint8_t*>(password.data()),
                       password.size()},
          .client_identifier = client_identifier,
          .server_identifier = server_identifier,
          .context = context,
          .key_stretching_config = KeyStretchingFunctionConfig{
              .variant = KeyStretchingFunctionVariant::RfcServerAuthentication,
          }});

  if (!finish_client_login) {
    throw std::runtime_error("Login failed");
  }

  // Client sends finish_client_login->finish_login_request to server

  auto finish_server_login =
      opaque_finish_server_login(OpaqueFinishServerLoginParams{
          .server_login_state = {start_server_login.server_login_state.data(),
                                 start_server_login.server_login_state.size()},
          .finish_login_request =
              {finish_client_login->finish_login_request.data(),
               finish_client_login->finish_login_request.size()},
          .context = "",
          .client_identifier = client_identifier,
          .server_identifier = server_identifier});

  return std::make_pair(finish_client_login->session_key,
                        finish_server_login.session_key);
}

int main() {
  const std::string client_identifier = "client1";
  const std::string server_identifier = "server1";
  const std::string context = "example.com";
  constexpr std::string_view password = "password123";

  try {
    const auto start_time = std::chrono::high_resolution_clock::now();
    auto server_setup = opaque_create_server_setup();

    const auto registration_start_time =
        std::chrono::high_resolution_clock::now();
    const auto registration_record =
        account_registration({server_setup.data(), server_setup.size()},
                             password, client_identifier, server_identifier);
    const auto registration_end_time =
        std::chrono::high_resolution_clock::now();

    std::cout << "Enregistrement du client en "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     registration_end_time - registration_start_time)
              << " Resulat: (hex) : [";
    print_hex({registration_record.data(), registration_record.size()});
    std::cout << "]\n";

    const auto login_start_time = std::chrono::high_resolution_clock::now();
    const auto [client_key, server_key] =
        account_login({server_setup.data(), server_setup.size()}, password,
                      client_identifier, server_identifier, context,
                      {registration_record.data(), registration_record.size()});

    const auto end_time = std::chrono::high_resolution_clock::now();

    std::cout << "Login reussi en "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     end_time - login_start_time)
              << " !\n";
    std::cout << "Temps total : "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     end_time - start_time)
              << " ms\n";

    std::cout << "Session key client (hex) : [";
    print_hex({client_key.data(), client_key.size()});
    std::cout << "]\n";

    std::cout << "Session key serveur (hex) : [";
    print_hex({server_key.data(), server_key.size()});
    std::cout << "]\n";

  } catch (const std::exception& e) {
    std::cerr << "Erreur : " << e.what() << "\n";
  }

  return 0;
}