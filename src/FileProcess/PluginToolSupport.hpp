#pragma once

#include "ToolCall.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <initializer_list>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace binjad::file_process::plugin {
	inline void RequireOnly(const rapidjson::Value& value, std::initializer_list<std::string_view> fields)
	{
		for (auto member = value.MemberBegin(); member != value.MemberEnd(); ++member)
		{
			const std::string_view name(member->name.GetString(), member->name.GetStringLength());
			if (std::find(fields.begin(), fields.end(), name) == fields.end())
				throw std::invalid_argument("unknown argument: " + std::string(name));
		}
	}

	inline std::string RequiredString(const rapidjson::Value& value, const char* name)
	{
		const auto member = value.FindMember(name);
		if (member == value.MemberEnd() || !member->value.IsString() || member->value.GetStringLength() == 0)
			throw std::invalid_argument(std::string(name) + " must be a non-empty string");
		return {member->value.GetString(), member->value.GetStringLength()};
	}

	inline std::string OptionalString(const rapidjson::Value& value, const char* name)
	{
		const auto member = value.FindMember(name);
		if (member == value.MemberEnd())
			return {};
		if (!member->value.IsString())
			throw std::invalid_argument(std::string(name) + " must be a string");
		return {member->value.GetString(), member->value.GetStringLength()};
	}

	inline bool OptionalBoolean(const rapidjson::Value& value, const char* name, bool fallback)
	{
		const auto member = value.FindMember(name);
		if (member == value.MemberEnd())
			return fallback;
		if (!member->value.IsBool())
			throw std::invalid_argument(std::string(name) + " must be a boolean");
		return member->value.GetBool();
	}

	inline std::pair<std::size_t, std::size_t> Pagination(const rapidjson::Value& value)
	{
		std::uint64_t offset = 0;
		std::uint64_t limit = 50;
		if (const auto member = value.FindMember("offset"); member != value.MemberEnd())
		{
			if (!member->value.IsUint64())
				throw std::invalid_argument("offset must be a non-negative integer");
			offset = member->value.GetUint64();
		}
		if (const auto member = value.FindMember("limit"); member != value.MemberEnd())
		{
			if (!member->value.IsUint64() || member->value.GetUint64() == 0 || member->value.GetUint64() > 1000)
				throw std::invalid_argument("limit must be an integer from 1 through 1000");
			limit = member->value.GetUint64();
		}
		if (offset > std::numeric_limits<std::size_t>::max())
			offset = std::numeric_limits<std::size_t>::max();
		return {static_cast<std::size_t>(offset), static_cast<std::size_t>(limit)};
	}

	inline bool ContainsInsensitive(std::string_view value, std::string_view query)
	{
		return std::search(value.begin(), value.end(), query.begin(), query.end(),
				   [](unsigned char left, unsigned char right) { return std::tolower(left) == std::tolower(right); })
			!= value.end();
	}

	template <typename Writer>
	void WriteAddress(Writer& writer, std::uint64_t address)
	{
		char buffer[19] {};
		std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(address));
		writer.String(buffer);
	}

	template <typename Writer, typename Collection, typename Callback>
	void WritePage(Writer& writer, const Collection& values, std::size_t offset, std::size_t limit, Callback callback)
	{
		const auto begin = std::min(offset, values.size());
		const auto end = std::min(values.size(), begin + std::min(limit, values.size() - begin));
		writer.StartObject();
		writer.Key("items");
		writer.StartArray();
		for (std::size_t index = begin; index < end; ++index)
			callback(writer, values[index]);
		writer.EndArray();
		writer.Key("total");
		writer.Uint64(values.size());
		writer.Key("offset");
		writer.Uint64(begin);
		writer.Key("limit");
		writer.Uint64(limit);
		writer.EndObject();
	}

	inline std::uint64_t ParseExpression(
		BinaryNinja::BinaryView& view, const rapidjson::Value& value, std::string_view field)
	{
		if (!value.IsString())
			throw std::invalid_argument(std::string(field) + " must be a string");
		std::uint64_t result = 0;
		std::string error;
		BinaryNinja::Ref<BinaryNinja::BinaryView> reference(&view);
		if (!BinaryNinja::BinaryView::ParseExpression(
				reference, std::string(value.GetString(), value.GetStringLength()), result, 0, error))
			throw std::invalid_argument(error.empty() ? std::string(field) + " is not a valid expression" : error);
		return result;
	}

	inline ipc::Reply JsonReply(const rapidjson::StringBuffer& buffer)
	{
		ipc::Reply reply;
		reply.set_success(true);
		reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
		return reply;
	}
}  // namespace binjad::file_process::plugin
