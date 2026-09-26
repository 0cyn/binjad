#include "binjad/security/Crypto.hpp"

#include "binjad/security/Random.hpp"
#include "PlatformRandom.hpp"

#include <trantor/utils/Utilities.h>
#include <trantor/utils/crypto/sha256.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <utility>

namespace binjad::security {
	namespace {
		std::string Hex(const unsigned char* bytes, std::size_t size)
		{
			static constexpr char alphabet[] = "0123456789abcdef";
			std::string output(size * 2, '\0');
			for (std::size_t index = 0; index < size; ++index)
			{
				output[index * 2] = alphabet[bytes[index] >> 4];
				output[index * 2 + 1] = alphabet[bytes[index] & 0xf];
			}
			return output;
		}
	}  // namespace

	std::string Sha256Hex(std::string_view value)
	{
		const auto digest = trantor::utils::sha256(value.data(), value.size());
		return Hex(digest.bytes, sizeof(digest.bytes));
	}

	std::string HmacSha256Hex(std::string_view key, std::string_view value)
	{
		constexpr std::size_t blockSize = 64;
		std::array<unsigned char, blockSize> normalizedKey {};
		if (key.size() > blockSize)
		{
			const auto digest = trantor::utils::sha256(key.data(), key.size());
			std::copy(std::begin(digest.bytes), std::end(digest.bytes), normalizedKey.begin());
		}
		else
		{
			std::copy(key.begin(), key.end(), normalizedKey.begin());
		}

		std::string inner(blockSize + value.size(), '\0');
		std::string outer(blockSize + 32, '\0');
		for (std::size_t index = 0; index < blockSize; ++index)
		{
			inner[index] = static_cast<char>(normalizedKey[index] ^ 0x36);
			outer[index] = static_cast<char>(normalizedKey[index] ^ 0x5c);
		}
		std::copy(value.begin(), value.end(), inner.begin() + blockSize);
		const auto innerDigest = trantor::utils::sha256(inner.data(), inner.size());
		std::copy(std::begin(innerDigest.bytes), std::end(innerDigest.bytes), outer.begin() + blockSize);
		const auto digest = trantor::utils::sha256(outer.data(), outer.size());
		return Hex(digest.bytes, sizeof(digest.bytes));
	}

	bool ConstantTimeEqual(std::string_view left, std::string_view right)
	{
		const std::size_t comparedSize = std::max(left.size(), right.size());
		std::size_t difference = left.size() ^ right.size();
		for (std::size_t index = 0; index < comparedSize; ++index)
		{
			const unsigned char leftByte = index < left.size() ? left[index] : 0;
			const unsigned char rightByte = index < right.size() ? right[index] : 0;
			difference |= leftByte ^ rightByte;
		}
		return difference == 0;
	}

	struct Sha256Hasher::Impl
	{
		SHA256_CTX context {};
		bool finalized = false;

		Impl() { trantor_sha256_init(&context); }
	};

	Sha256Hasher::Sha256Hasher() : impl_(std::make_unique<Impl>()) {}
	Sha256Hasher::Sha256Hasher(Sha256Hasher&&) noexcept = default;
	Sha256Hasher& Sha256Hasher::operator=(Sha256Hasher&&) noexcept = default;
	Sha256Hasher::~Sha256Hasher() = default;

	void Sha256Hasher::Update(std::string_view value)
	{
		if (!impl_ || impl_->finalized)
			return;
		trantor_sha256_update(&impl_->context, reinterpret_cast<const std::uint8_t*>(value.data()), value.size());
	}

	std::string Sha256Hasher::FinalHex()
	{
		if (!impl_ || impl_->finalized)
			return {};
		std::array<unsigned char, 32> digest {};
		trantor_sha256_final(&impl_->context, digest.data());
		impl_->finalized = true;
		return Hex(digest.data(), digest.size());
	}

	namespace {
		std::string Hex(std::span<const unsigned char> bytes)
		{
			return Hex(bytes.data(), bytes.size());
		}

		std::string Base64Url(std::span<const unsigned char> bytes)
		{
			static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
			std::string output;
			output.reserve((bytes.size() * 4 + 2) / 3);
			std::size_t offset = 0;
			while (offset + 3 <= bytes.size())
			{
				const std::uint32_t value = (static_cast<std::uint32_t>(bytes[offset]) << 16)
					| (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) | bytes[offset + 2];
				output.push_back(alphabet[(value >> 18) & 0x3f]);
				output.push_back(alphabet[(value >> 12) & 0x3f]);
				output.push_back(alphabet[(value >> 6) & 0x3f]);
				output.push_back(alphabet[value & 0x3f]);
				offset += 3;
			}
			if (offset < bytes.size())
			{
				std::uint32_t value = static_cast<std::uint32_t>(bytes[offset]) << 16;
				if (offset + 1 < bytes.size())
					value |= static_cast<std::uint32_t>(bytes[offset + 1]) << 8;
				output.push_back(alphabet[(value >> 18) & 0x3f]);
				output.push_back(alphabet[(value >> 12) & 0x3f]);
				if (offset + 1 < bytes.size())
					output.push_back(alphabet[(value >> 6) & 0x3f]);
			}
			return output;
		}

		template <typename Encode>
		RandomStringResult Generate(Encode encode)
		{
			std::array<unsigned char, 32> bytes {};
			if (auto error = FillSecureRandom(bytes); !error.empty())
				return {{}, std::move(error)};
			return {encode(bytes), {}};
		}
	}  // namespace

	RandomStringResult GenerateHex256()
	{
		return Generate([](const auto& bytes) { return Hex(bytes); });
	}

	RandomStringResult GenerateBase64Url256()
	{
		return Generate([](const auto& bytes) { return Base64Url(bytes); });
	}
}  // namespace binjad::security
