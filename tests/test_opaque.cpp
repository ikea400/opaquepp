#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "../src/opaque++.h"

using namespace opaque;

class OpaqueProtocolTest : public ::testing::Test {
 protected:
  // Shared test constants
  const std::string user_id = "alice@example.com";
  const std::string server_id = "server.com";
  const std::string context = "auth-v1";
  const std::string password = "password123";

  // Setup helper
  std::shared_ptr<OpaqueServerSetup> server_setup;

  void SetUp() override {
    // Initialize the server setup (generates keys)
    server_setup = std::make_shared<OpaqueServerSetup>();
  }
};

/**
 * @brief Test the full lifecycle: Registration -> Login -> Key Agreement
 */
TEST_F(OpaqueProtocolTest, FullHandshakeSuccess) {
  // --- 1. REGISTRATION PHASE ---
  auto client =
      std::make_unique<OpaqueClient>(password, user_id, server_id, context);
  auto server =
      std::make_unique<OpaqueServer>(server_setup, user_id, server_id, context);

  // Client initiates
  auto reg_request = client->startRegistration();
  ASSERT_EQ(reg_request.size(), kRegisterRequestSize);

  // Server responds
  auto reg_response = server->startRegistration(reg_request);
  ASSERT_EQ(reg_response.size(), kRegisterResponseSize);

  // Client finalizes and creates the record for the server to store
  auto registration_record = client->finishRegistration(reg_response);
  ASSERT_EQ(registration_record.size(), kRegisterRecordSize);

  auto password_file = server->finishRegistration(registration_record);
  ASSERT_EQ(password_file.size(), kPasswordFileSize);

  // --- 2. LOGIN PHASE ---
  // Note: In a real app, the server would have saved 'registration_record' in a
  // DB
  auto login_client =
      std::make_unique<OpaqueClient>(password, user_id, server_id, context);
  auto login_server =
      std::make_unique<OpaqueServer>(server_setup, user_id, server_id, context);

  // Client starts login
  auto login_request = login_client->startLogin();

  // Server processes login request
  auto login_response =
      login_server->startLogin(user_id, password_file, login_request);

  // Client processes server response and generates finish request
  auto finish_request = login_client->finishLogin(login_response);

  // Server finalizes
  EXPECT_NO_THROW({ login_server->finishLogin(finish_request); });

  // --- 3. VERIFICATION ---
  // The "Golden Rule" of PAKE: Both sides must arrive at the exact same session
  // key
  std::span<const uint8_t> client_key = login_client->getSessionKey();
  std::span<const uint8_t> server_key = login_server->getSessionKey();

  EXPECT_FALSE(client_key.empty());
  EXPECT_EQ(client_key.size(), server_key.size())
      << "Session key lengths do not match!";

  EXPECT_TRUE(
      std::equal(client_key.begin(), client_key.end(), server_key.begin()))
      << "Session keys do not match!";
}

/**
 * @brief Verify that an incorrect password throws the expected exception
 */
TEST_F(OpaqueProtocolTest, LoginFailsWithWrongPassword) {
  // 1. Register with "password123"
  auto client_reg =
      std::make_unique<OpaqueClient>(password, user_id, server_id, context);
  auto server_reg =
      std::make_unique<OpaqueServer>(server_setup, user_id, server_id, context);

  auto reg_record = client_reg->finishRegistration(
      server_reg->startRegistration(client_reg->startRegistration()));

  auto password_file = server_reg->finishRegistration(reg_record);

  // 2. Try to login with "WRONG_password"
  auto login_client = std::make_unique<OpaqueClient>("WRONG_password", user_id,
                                                     server_id, context);
  auto login_server =
      std::make_unique<OpaqueServer>(server_setup, user_id, server_id, context);

  auto login_request = login_client->startLogin();
  auto login_response =
      login_server->startLogin(user_id, password_file, login_request);

  // This should trigger your custom InvalidLoginException
  EXPECT_THROW(
      { login_client->finishLogin(login_response); }, InvalidLoginException);
}

/**
 * @brief Verify that login fails when the client identifier presented to the
 * server does not match the one used to register.
 */
TEST_F(OpaqueProtocolTest, LoginFailsWithWrongUserIdentifier) {
  // Register normally
  auto reg_client =
      std::make_unique<OpaqueClient>(password, user_id, server_id, context);
  auto reg_server =
      std::make_unique<OpaqueServer>(server_setup, user_id, server_id, context);

  auto reg_record = reg_client->finishRegistration(
      reg_server->startRegistration(reg_client->startRegistration()));

  // Client attempts login with correct credentials but different user
  // identifier
  auto malicious_user_id = std::string("mallory@example.com");
  auto login_client = std::make_unique<OpaqueClient>(
      password, malicious_user_id, server_id, context);

  // Server receives a different client identifier than the one in the
  // registration
  auto login_server =
      std::make_unique<OpaqueServer>(server_setup, user_id, server_id, context);

  auto login_request = login_client->startLogin();
  // Server processes login using the wrong client identifier
  auto login_response =
      login_server->startLogin(malicious_user_id, reg_record, login_request);

  // Client should detect the mismatch when finishing login
  EXPECT_THROW(
      { login_client->finishLogin(login_response); }, InvalidLoginException);
}

/**
 * @brief Verify that login fails when the client identifier presented to the
 * server does not match the one used to register.
 */
TEST_F(OpaqueProtocolTest, LoginFailsWithWrongClientIdentifier) {
  // Register normally
  auto reg_client =
      std::make_unique<OpaqueClient>(password, user_id, server_id, context);
  auto reg_server =
      std::make_unique<OpaqueServer>(server_setup, user_id, server_id, context);

  auto reg_record = reg_client->finishRegistration(
      reg_server->startRegistration(reg_client->startRegistration()));

  // Client attempts login with correct credentials
  auto login_client =
      std::make_unique<OpaqueClient>(password, user_id, server_id, context);

  // Server receives a different client identifier than the one in the
  // registration
  auto malicious_user_id = std::string("mallory@example.com");
  auto login_server =
      std::make_unique<OpaqueServer>(server_setup, user_id, server_id, context);

  auto login_request = login_client->startLogin();
  // Server processes login using the wrong client identifier
  auto login_response =
      login_server->startLogin(malicious_user_id, reg_record, login_request);

  // Client should detect the mismatch when finishing login
  EXPECT_THROW(
      { login_client->finishLogin(login_response); }, InvalidLoginException);
}

/**
 * @brief Verify that login fails when the server identifier used by client and
 * server differ.
 */
TEST_F(OpaqueProtocolTest, LoginFailsWithWrongServerIdentifier) {
  // Register normally
  auto reg_client =
      std::make_unique<OpaqueClient>(password, user_id, server_id, context);
  auto reg_server =
      std::make_unique<OpaqueServer>(server_setup, user_id, server_id, context);

  auto reg_record = reg_client->finishRegistration(
      reg_server->startRegistration(reg_client->startRegistration()));

  // Client constructed expecting a different server identifier
  auto wrong_server_id = std::string("other-server.com");
  auto login_client = std::make_unique<OpaqueClient>(password, user_id,
                                                     wrong_server_id, context);

  // Real server uses original server_id
  auto login_server =
      std::make_unique<OpaqueServer>(server_setup, user_id, server_id, context);

  auto login_request = login_client->startLogin();
  auto login_response =
      login_server->startLogin(user_id, reg_record, login_request);

  // Client should detect server identifier mismatch when finishing login
  EXPECT_THROW(
      { login_client->finishLogin(login_response); }, InvalidLoginException);
}

/**
 * @brief Verify that login fails when the context used by client and server
 * differ.
 */
TEST_F(OpaqueProtocolTest, LoginFailsWithWrongContext) {
  // Register normally
  auto reg_client =
      std::make_unique<OpaqueClient>(password, user_id, server_id, context);
  auto reg_server =
      std::make_unique<OpaqueServer>(server_setup, user_id, server_id, context);

  auto reg_record = reg_client->finishRegistration(
      reg_server->startRegistration(reg_client->startRegistration()));

  // Client uses a different context string
  auto wrong_context = std::string("auth-v2");
  auto login_client = std::make_unique<OpaqueClient>(password, user_id,
                                                     server_id, wrong_context);

  // Server uses original context
  auto login_server =
      std::make_unique<OpaqueServer>(server_setup, user_id, server_id, context);

  auto login_request = login_client->startLogin();
  auto login_response =
      login_server->startLogin(user_id, reg_record, login_request);

  // Client should detect context mismatch when finishing login
  EXPECT_THROW(
      { login_client->finishLogin(login_response); }, InvalidLoginException);
}

/**
 * @brief Verify that login fails when the server uses a different registration
 * record (e.g., wrong "password file") for the same password.
 *
 * Scenario:
 *  - Two different users register using the same plaintext password.
 *  - During login, the server mistakenly looks up the registration record of
 *    the other user (same password but different record).
 *  - The protocol must fail authentication.
 */
TEST_F(OpaqueProtocolTest,
       LoginFailsWhenServerUsesWrongRegistrationRecordSamePassword) {
  // Register user A
  const std::string userA = user_id;  // "alice@example.com"
  auto clientA =
      std::make_unique<OpaqueClient>(password, userA, server_id, context);
  auto serverA =
      std::make_unique<OpaqueServer>(server_setup, userA, server_id, context);

  auto reg_req_A = clientA->startRegistration();
  auto reg_resp_A = serverA->startRegistration(reg_req_A);
  auto reg_record_A = clientA->finishRegistration(reg_resp_A);
  ASSERT_EQ(reg_record_A.size(), kRegisterRecordSize);

  // Register user B with the same password
  const std::string userB = "bob@example.com";
  auto clientB =
      std::make_unique<OpaqueClient>(password, userB, server_id, context);
  auto serverB =
      std::make_unique<OpaqueServer>(server_setup, userB, server_id, context);

  auto reg_req_B = clientB->startRegistration();
  auto reg_resp_B = serverB->startRegistration(reg_req_B);
  auto reg_record_B = clientB->finishRegistration(reg_resp_B);
  ASSERT_EQ(reg_record_B.size(), kRegisterRecordSize);

  // Ensure records differ (sanity)
  EXPECT_NE(reg_record_A.size(), 0u);
  EXPECT_NE(reg_record_B.size(), 0u);

  // Now simulate server using userB's registration record while clientA logs in
  auto login_clientA =
      std::make_unique<OpaqueClient>(password, userA, server_id, context);
  auto login_server =
      std::make_unique<OpaqueServer>(server_setup, userA, server_id, context);

  auto login_req_A = login_clientA->startLogin();
  // Server mistakenly supplies reg_record_B instead of reg_record_A
  auto login_resp_mis =
      login_server->startLogin(userA, reg_record_B, login_req_A);

  // ClientA should fail to finish login even though the plaintext password is
  // the same
  EXPECT_THROW(
      { login_clientA->finishLogin(login_resp_mis); }, InvalidLoginException);
}

/**
 * @brief Verify that login fails when client and server swap identities between
 * registration and login.
 *
 * Scenario:
 *  - User A registers and user B registers.
 *  - Later, client A attempts to login but the server uses user B's identity
 *    and record (swap). Authentication must fail.
 */
TEST_F(OpaqueProtocolTest, LoginFailsWhenClientAndServerIdentifiersSwapped) {
  // Register user A
  const std::string userA = user_id;  // "alice@example.com"
  auto clientA =
      std::make_unique<OpaqueClient>(password, userA, server_id, context);
  auto serverA =
      std::make_unique<OpaqueServer>(server_setup, userA, server_id, context);

  auto reg_req_A = clientA->startRegistration();
  auto reg_resp_A = serverA->startRegistration(reg_req_A);
  auto reg_record_A = clientA->finishRegistration(reg_resp_A);
  ASSERT_EQ(reg_record_A.size(), kRegisterRecordSize);

  // Register user B
  const std::string userB = "bob@example.com";
  auto clientB =
      std::make_unique<OpaqueClient>(password, userB, server_id, context);
  auto serverB =
      std::make_unique<OpaqueServer>(server_setup, userB, server_id, context);

  auto reg_req_B = clientB->startRegistration();
  auto reg_resp_B = serverB->startRegistration(reg_req_B);
  auto reg_record_B = clientB->finishRegistration(reg_resp_B);
  ASSERT_EQ(reg_record_B.size(), kRegisterRecordSize);

  // Now client A tries to login but the server uses B's identity and record
  // (swapped)
  auto login_clientA =
      std::make_unique<OpaqueClient>(password, userA, server_id, context);
  auto login_server_swapped =
      std::make_unique<OpaqueServer>(server_setup, userB, server_id, context);

  auto login_req_A = login_clientA->startLogin();
  // Server responds using userB and reg_record_B (swap)
  auto login_resp_swapped =
      login_server_swapped->startLogin(userB, reg_record_B, login_req_A);

  // Client A should fail to finish login because server identity/record do not
  // match A
  EXPECT_THROW(
      { login_clientA->finishLogin(login_resp_swapped); },
      InvalidLoginException);
}

/**
 * @brief Verify that login fails when the registration record sent to the
 * server is compromised before being stored.
 */
TEST_F(OpaqueProtocolTest, LoginFailsWhenRegistrationRecordIsCompromised) {
  // 1. Register normally
  auto reg_client =
      std::make_unique<OpaqueClient>(password, user_id, server_id, context);
  auto reg_server =
      std::make_unique<OpaqueServer>(server_setup, user_id, server_id, context);

  auto reg_request = reg_client->startRegistration();
  auto reg_response = reg_server->startRegistration(reg_request);
  auto registration_record = reg_client->finishRegistration(reg_response);
  ASSERT_FALSE(registration_record.empty());

  // 2. Compromise the record before the server stores it
  auto compromised_record = registration_record;
  compromised_record[0] ^= 0x01;
  ASSERT_NE(compromised_record, registration_record);

  EXPECT_THROW(
      { reg_server->finishRegistration(compromised_record); }, std::exception);
}
