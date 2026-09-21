#pragma once

#include <string>
#include <string_view>
#include <memory>

namespace binjad::security
{
std::string Sha256Hex(std::string_view value);
std::string HmacSha256Hex(std::string_view key, std::string_view value);
bool ConstantTimeEqual(std::string_view left, std::string_view right);

class Sha256Hasher
{
  public:
    Sha256Hasher();
    Sha256Hasher(const Sha256Hasher&) = delete;
    Sha256Hasher& operator=(const Sha256Hasher&) = delete;
    Sha256Hasher(Sha256Hasher&&) noexcept;
    Sha256Hasher& operator=(Sha256Hasher&&) noexcept;
    ~Sha256Hasher();

    void Update(std::string_view value);
    std::string FinalHex();

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
