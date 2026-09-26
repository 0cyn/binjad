#pragma once

#include "ToolCall.hpp"

#include <algorithm>
#include <initializer_list>
#include <optional>
#include <string_view>

namespace binjad::mcp::schema {
	enum class PropertyType
	{
		String,
		Boolean,
		Integer,
		Object,
		Array,
		StringArray,
		ObjectArray,
		StringOrInteger,
		StringOrNull,
		Any,
	};

	struct Property
	{
		std::string_view name;
		PropertyType type = PropertyType::String;
		bool required = false;
		std::optional<std::uint64_t> minimum;
		std::optional<std::uint64_t> maximum;
		std::optional<std::uint64_t> defaultValue;
		std::string_view defaultString;
		std::optional<std::uint64_t> minimumLength;
		std::optional<std::uint64_t> minimumItems;
		std::optional<std::uint64_t> maximumItems;
		std::string_view description;
		std::initializer_list<std::string_view> values;
		std::initializer_list<Property> itemProperties;
	};

	inline Property String(std::string_view name, bool required = false, std::string_view description = {})
	{
		return {.name = name,
			.required = required,
			.minimumLength = required ? std::optional<std::uint64_t>(1) : std::nullopt,
			.description = description};
	}

	inline Property NonEmptyString(std::string_view name, bool required = false, std::string_view description = {})
	{
		return {.name = name, .required = required, .minimumLength = 1, .description = description};
	}

	inline Property Boolean(std::string_view name, bool required = false, std::string_view description = {})
	{
		return {.name = name, .type = PropertyType::Boolean, .required = required, .description = description};
	}

	inline Property Integer(std::string_view name, bool required = false, std::optional<std::uint64_t> minimum = {},
		std::optional<std::uint64_t> maximum = {}, std::optional<std::uint64_t> defaultValue = {},
		std::string_view description = {})
	{
		return {.name = name,
			.type = PropertyType::Integer,
			.required = required,
			.minimum = minimum,
			.maximum = maximum,
			.defaultValue = defaultValue,
			.description = description};
	}

	inline Property Object(std::string_view name, bool required = false, std::string_view description = {})
	{
		return {.name = name, .type = PropertyType::Object, .required = required, .description = description};
	}

	inline Property Array(std::string_view name, bool required = false, std::string_view description = {})
	{
		return {.name = name, .type = PropertyType::Array, .required = required, .description = description};
	}

	inline Property StringArray(std::string_view name, bool required = false, std::string_view description = {})
	{
		return {.name = name, .type = PropertyType::StringArray, .required = required, .description = description};
	}

	inline Property ObjectArray(std::string_view name, bool required, std::initializer_list<Property> itemProperties,
		std::optional<std::uint64_t> minimumItems = {}, std::optional<std::uint64_t> maximumItems = {},
		std::string_view description = {})
	{
		return {.name = name,
			.type = PropertyType::ObjectArray,
			.required = required,
			.minimumItems = minimumItems,
			.maximumItems = maximumItems,
			.description = description,
			.itemProperties = itemProperties};
	}

	inline Property StringOrInteger(std::string_view name, bool required = false,
		std::optional<std::uint64_t> minimum = {}, std::optional<std::uint64_t> maximum = {},
		std::string_view description = {})
	{
		return {.name = name,
			.type = PropertyType::StringOrInteger,
			.required = required,
			.minimum = minimum,
			.maximum = maximum,
			.minimumLength = required ? std::optional<std::uint64_t>(1) : std::nullopt,
			.description = description};
	}

	inline Property StringOrNull(std::string_view name, bool required = false, std::string_view description = {})
	{
		return {.name = name,
			.type = PropertyType::StringOrNull,
			.required = required,
			.minimumLength = 1,
			.description = description};
	}

	inline Property Any(std::string_view name, bool required = false, std::string_view description = {})
	{
		return {.name = name, .type = PropertyType::Any, .required = required, .description = description};
	}

	inline Property Enum(std::string_view name, bool required, std::initializer_list<std::string_view> values,
		std::string_view description = {})
	{
		return {.name = name, .required = required, .description = description, .values = values};
	}

	inline Property EnumWithDefault(std::string_view name, bool required,
		std::initializer_list<std::string_view> values, std::string_view defaultValue,
		std::string_view description = {})
	{
		return {.name = name,
			.required = required,
			.defaultString = defaultValue,
			.description = description,
			.values = values};
	}

	inline void WriteObject(ToolCallSchemaWriter& writer, std::initializer_list<Property> properties)
	{
		writer.StartObject();
		writer.Key("type");
		writer.String("object");
		writer.Key("properties");
		writer.StartObject();
		for (const auto& property : properties)
		{
			writer.Key(property.name.data(), static_cast<rapidjson::SizeType>(property.name.size()));
			writer.StartObject();
			if (property.type != PropertyType::Any)
			{
				writer.Key("type");
				switch (property.type)
				{
				case PropertyType::String:
					writer.String("string");
					break;
				case PropertyType::Boolean:
					writer.String("boolean");
					break;
				case PropertyType::Integer:
					writer.String("integer");
					break;
				case PropertyType::Object:
					writer.String("object");
					break;
				case PropertyType::Array:
				case PropertyType::StringArray:
				case PropertyType::ObjectArray:
					writer.String("array");
					break;
				case PropertyType::StringOrInteger:
					writer.StartArray();
					writer.String("integer");
					writer.String("string");
					writer.EndArray();
					break;
				case PropertyType::StringOrNull:
					writer.StartArray();
					writer.String("string");
					writer.String("null");
					writer.EndArray();
					break;
				case PropertyType::Any:
					break;
				}
			}
			if (property.type == PropertyType::StringArray)
			{
				writer.Key("items");
				writer.StartObject();
				writer.Key("type");
				writer.String("string");
				writer.EndObject();
			}
			else if (property.type == PropertyType::ObjectArray)
			{
				writer.Key("items");
				writer.StartObject();
				writer.Key("type");
				writer.String("object");
				writer.Key("properties");
				writer.StartObject();
				for (const auto& item : property.itemProperties)
				{
					writer.Key(item.name.data(), static_cast<rapidjson::SizeType>(item.name.size()));
					writer.StartObject();
					writer.Key("type");
					writer.String("string");
					if (!item.description.empty())
					{
						writer.Key("description");
						writer.String(
							item.description.data(), static_cast<rapidjson::SizeType>(item.description.size()));
					}
					writer.EndObject();
				}
				writer.EndObject();
				if (std::any_of(property.itemProperties.begin(), property.itemProperties.end(), [](const auto& item) {
						return item.required;
					}))
				{
					writer.Key("required");
					writer.StartArray();
					for (const auto& item : property.itemProperties)
						if (item.required)
							writer.String(item.name.data(), static_cast<rapidjson::SizeType>(item.name.size()));
					writer.EndArray();
				}
				writer.Key("additionalProperties");
				writer.Bool(false);
				writer.EndObject();
			}
			if (property.minimum)
			{
				writer.Key("minimum");
				writer.Uint64(*property.minimum);
			}
			if (property.maximum)
			{
				writer.Key("maximum");
				writer.Uint64(*property.maximum);
			}
			if (property.defaultValue)
			{
				writer.Key("default");
				writer.Uint64(*property.defaultValue);
			}
			if (!property.defaultString.empty())
			{
				writer.Key("default");
				writer.String(
					property.defaultString.data(), static_cast<rapidjson::SizeType>(property.defaultString.size()));
			}
			if (property.minimumLength)
			{
				writer.Key("minLength");
				writer.Uint64(*property.minimumLength);
			}
			if (property.minimumItems)
			{
				writer.Key("minItems");
				writer.Uint64(*property.minimumItems);
			}
			if (property.maximumItems)
			{
				writer.Key("maxItems");
				writer.Uint64(*property.maximumItems);
			}
			if (property.values.size() != 0)
			{
				writer.Key("enum");
				writer.StartArray();
				for (const auto value : property.values)
					writer.String(value.data(), static_cast<rapidjson::SizeType>(value.size()));
				writer.EndArray();
			}
			if (!property.description.empty())
			{
				writer.Key("description");
				writer.String(
					property.description.data(), static_cast<rapidjson::SizeType>(property.description.size()));
			}
			writer.EndObject();
		}
		writer.EndObject();
		if (std::any_of(properties.begin(), properties.end(), [](const auto& property) { return property.required; }))
		{
			writer.Key("required");
			writer.StartArray();
			for (const auto& property : properties)
				if (property.required)
					writer.String(property.name.data(), static_cast<rapidjson::SizeType>(property.name.size()));
			writer.EndArray();
		}
		writer.Key("additionalProperties");
		writer.Bool(false);
		writer.EndObject();
	}
}  // namespace binjad::mcp::schema
