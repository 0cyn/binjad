#include "binjad/reference/FriendlyReference.hpp"

#include "binjad/reference/FriendlyWordsData.hpp"
#include "binjad/security/Random.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <unordered_set>
#include <vector>

namespace binjad::reference {
	namespace {
		struct Dictionary
		{
			Dictionary()
			{
				for (const auto word : detail::kFriendlyWords)
				{
					if (word.size() < 4 || word.size() > 12
						|| !std::all_of(word.begin(), word.end(), [](char character) {
							   return character >= 'a' && character <= 'z';
						   }))
						throw std::logic_error("friendly-word data contains an invalid word");
					if (!set.insert(word).second)
						throw std::logic_error("friendly-word data contains a duplicate word");
					words.push_back(word);
				}
				if (words.size() != 16384)
					throw std::logic_error("friendly-word data must contain exactly 16384 words");
			}

			std::vector<std::string_view> words;
			std::unordered_set<std::string_view> set;
		};

		const Dictionary& Words()
		{
			static const Dictionary dictionary;
			return dictionary;
		}

		unsigned HexDigit(char character)
		{
			return character <= '9' ?
				static_cast<unsigned>(character - '0') :
				static_cast<unsigned>(character - 'a' + 10);
		}

		std::string Candidate(std::string_view randomHex)
		{
			std::string output;
			output.reserve(48);
			for (std::size_t wordIndex = 0; wordIndex < 4; ++wordIndex)
			{
				std::uint16_t value = 0;
				for (std::size_t digit = 0; digit < 4; ++digit)
					value = static_cast<std::uint16_t>((value << 4) | HexDigit(randomHex[wordIndex * 4 + digit]));
				const auto word = Words().words[value & 0x3fff];
				output.push_back(static_cast<char>(word.front() - 'a' + 'A'));
				output.append(word.substr(1));
			}
			return output;
		}
	}  // namespace

	FriendlyReferenceResult FriendlyReferencePool::Acquire()
	{
		for (int attempt = 0; attempt < 100; ++attempt)
		{
			auto random = security::GenerateHex256();
			if (!random.value)
				return {{}, "cannot generate friendly reference: " + random.error};
			auto candidate = Candidate(*random.value);
			std::lock_guard lock(mutex_);
			if (active_.insert(candidate).second)
				return {std::move(candidate), {}};
		}
		return {{}, "cannot generate a unique friendly reference"};
	}

	bool FriendlyReferencePool::Release(std::string_view reference)
	{
		std::lock_guard lock(mutex_);
		return active_.erase(std::string(reference)) != 0;
	}

	std::size_t FriendlyReferencePool::Size() const
	{
		std::lock_guard lock(mutex_);
		return active_.size();
	}

	bool IsFriendlyReference(std::string_view reference)
	{
		std::array<std::string, 4> words;
		std::size_t wordIndex = 0;
		for (const char character : reference)
		{
			if (character >= 'A' && character <= 'Z')
			{
				if (wordIndex == words.size() || !words[wordIndex].empty())
					++wordIndex;
				if (wordIndex >= words.size())
					return false;
				words[wordIndex].push_back(static_cast<char>(character - 'A' + 'a'));
			}
			else if (character >= 'a' && character <= 'z' && !words[wordIndex].empty())
			{
				words[wordIndex].push_back(character);
			}
			else
			{
				return false;
			}
		}
		if (wordIndex != words.size() - 1)
			return false;
		return std::all_of(words.begin(), words.end(), [](const auto& word) { return Words().set.contains(word); });
	}

	std::size_t FriendlyWordCount()
	{
		return Words().words.size();
	}
}  // namespace binjad::reference
