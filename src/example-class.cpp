#include <chrono>
#include <cstdint>
#include <exception>
#include <ios>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "opaque++.h"

using namespace opaque;

static void print_hex(const std::span<const std::uint8_t> data) {
  for (const auto& byte : data) {
    std::cout << std::hex << static_cast<int>(byte) << " ";
  }
  std::cout << std::dec << "\n";  // Reset to decimal
}

static auto accountRegistration(const OpaqueServerSetupPtr& serverSetup,
                                const std::string_view password,
                                const std::string& clientIdentifier,
                                const std::string& serverIdentifier) {
  OpaqueClient client(password, clientIdentifier, serverIdentifier, "");
  OpaqueServer server(serverSetup, clientIdentifier, serverIdentifier, "");

  const auto registrationRequest = client.startRegistration();
  std::cout << registrationRequest.size()
            << " bytes de demande d'enregistrement generer par le client\n";

  // Client sends registrationRequest to server

  const auto registrationResponse =
      server.startRegistration(registrationRequest);
  std::cout << registrationResponse.size()
            << " bytes de reponse d'enregistrement generer par le serveur\n";

  // Server sends registrationResponse to client

  const auto registrationRecord =
      client.finishRegistration(registrationResponse);

  std::cout << registrationRecord.size()
            << " bytes de record d'enregistrement generer par le client\n";

  // Client sends registrationRecord to server

  const auto passwordFile = server.finishRegistration(registrationRecord);

  std::cout
      << passwordFile.size()
      << " bytes de password file d'enregistrement generer par le serveur\n";

  return passwordFile;
}

static auto accountLogin(
    const OpaqueServerSetupPtr& serverSetup, const std::string_view password,
    const std::string& clientIdentifier, const std::string& serverIdentifier,
    const std::string& context,
    const std::span<const std::uint8_t> registration_record) {
  OpaqueClient client(password, clientIdentifier, serverIdentifier, context);
  OpaqueServer server(serverSetup, clientIdentifier, serverIdentifier, context);

  const auto loginRequest = client.startLogin();
  std::cout << loginRequest.size()
            << " bytes de demande de login generer par le client\n";

  // Client sends loginRequest to server

  const auto loginResponse =
      server.startLogin(clientIdentifier, registration_record, loginRequest);
  std::cout << loginResponse.size()
            << " bytes de reponse de login generer par le serveur\n";

  // Server sends loginResponse to client

  const auto finishLoginRequest = client.finishLogin(loginResponse);
  std::cout
      << finishLoginRequest.size()
      << " bytes de demande de finalisation de login generer par le client\n";

  // Client sends finishLoginRequest to server

  server.finishLogin(finishLoginRequest);

  // Client and server should now have the same session key

  std::cout << client.getSessionKey().size()
            << " bytes de session key generer par le client/serveur\n";
  std::cout << client.getExportKey().size()
            << " bytes de export key generer par le client\n";

  return std::make_pair(client.getSessionKey(), server.getSessionKey());
}

int main() {
  const std::string client_identifier = "client1";
  const std::string server_identifier = "server1";
  const std::string context = "example.com";
  constexpr std::string_view password = "password123";

  try {
    const auto start_time = std::chrono::high_resolution_clock::now();
    auto server_setup = std::make_shared<OpaqueServerSetup>();

    const auto registration_start_time =
        std::chrono::high_resolution_clock::now();
    const auto registrationRecord = accountRegistration(
        server_setup, password, client_identifier, server_identifier);

    const auto registration_end_time =
        std::chrono::high_resolution_clock::now();

    std::cout << "Enregistrement du client en "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     registration_end_time - registration_start_time)
              << " Resulat: (hex) : [";
    print_hex({registrationRecord.data(), registrationRecord.size()});
    std::cout << "]\n";

    const auto login_start_time = std::chrono::high_resolution_clock::now();
    const auto [clientKey, serverKey] =
        accountLogin(server_setup, password, client_identifier,
                     server_identifier, context, registrationRecord);

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
    print_hex({clientKey.data(), clientKey.size()});
    std::cout << "]\n";

    std::cout << "Session key serveur (hex) : [";
    print_hex({serverKey.data(), serverKey.size()});
    std::cout << "]\n";

  } catch (const std::exception& e) {
    std::cerr << "Erreur : " << e.what() << "\n";
  }

  return 0;
}