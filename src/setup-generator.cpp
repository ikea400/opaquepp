#include <functional>
#include <span>
#include <string_view>
#include <format>
#include <iostream>

#include "opaque++.h"

std::string formatHex(std::span<const uint8_t> data) {
  std::string result;
  result.reserve(data.size() * 2);
  for (uint8_t b : data) {
    // {:02x} prints the hex in lowercase with a leading zero if needed
    result += std::format("{:02x}", b);
  }
  return result;
}

std::string formatBase64(std::span<const uint8_t> data) {
  static constexpr std::string_view alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string result;
  result.reserve(((data.size() + 2) / 3) * 4);

  uint32_t val = 0;
  int valb = -6;
  for (uint8_t c : data) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      result.push_back(alphabet[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }

  if (valb > -6) result.push_back(alphabet[((val << 8) >> (valb + 8)) & 0x3F]);
  while (result.size() % 4) result.push_back('=');

  return result;
}

int main(int argc, char** argv) {
  std::function<std::string(std::span<const uint8_t>)> formater;

  for (size_t i = 0; i < argc; ++i) {
    std::string_view arg(argv[i]);
    if (arg == "--hex") {
      formater = formatHex;
    } else if (arg == "--base64" || arg == "-b64") {
      formater = formatBase64;
    }
  }

  if (!formater) formater = formatBase64;

  opaque::OpaqueServerSetup serverSetup;

  std::cout << formater(serverSetup.get()) << std::endl;

  return 0;
}