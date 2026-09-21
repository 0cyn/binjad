#include "../PluginToolSupport.hpp"
#include "../ToolCall.hpp"
#include "../ToolSupport.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace binjad {
	using namespace file_process;
	using namespace file_process::plugin;

	namespace {
		struct Match
		{
			BinaryNinja::SimilarityEntityId primaryEntity;
			BinaryNinja::SimilarityEntityId secondaryEntity;
			BinaryNinja::SimilarityResultId result;
			std::uint64_t primaryAddress = 0;
			std::uint64_t secondaryAddress = 0;
			std::string primaryName;
			std::string secondaryName;
			std::uint8_t similarity = 0;
			std::uint8_t confidence = 0;
		};

		std::vector<Match> CollectMatches(const binary_ninja::DiffTools::State& state)
		{
			std::vector<Match> matches;
			for (const auto primaryEntity : state.primaryNode->GetEntities())
			{
				const auto primaryInfo = state.primaryNode->GetEntity(primaryEntity);
				if (!primaryInfo || primaryInfo->type != SimilarityEntityFunction)
					continue;
				for (const auto resultId : state.primaryNode->GetResults(primaryEntity))
				{
					const auto result = state.primaryNode->GetResult(resultId);
					if (!result || result->providerId != state.provider->GetId()
						|| result->target.nodeId != state.secondaryNode->GetId())
						continue;
					const auto secondaryInfo = state.secondaryNode->GetEntity(result->target.entityId);
					if (!secondaryInfo)
						continue;
					matches.push_back({primaryEntity, result->target.entityId, resultId, primaryInfo->address,
						secondaryInfo->address, primaryInfo->name, secondaryInfo->name, result->similarity,
						result->confidence});
				}
			}
			return matches;
		}

		std::uint64_t DiffAddress(BinaryNinja::BinaryView& view, const rapidjson::Value& arguments, const char* name)
		{
			const auto member = arguments.FindMember(name);
			if (member == arguments.MemberEnd() || !member->value.IsString() || member->value.GetStringLength() == 0)
				throw std::invalid_argument(std::string(name) + " must be a non-empty address expression");
			return ParseExpression(view, member->value, name);
		}

		std::size_t UnsignedArgument(
			const rapidjson::Value& arguments, const char* name, std::size_t fallback, std::size_t maximum)
		{
			const auto member = arguments.FindMember(name);
			if (member == arguments.MemberEnd())
				return fallback;
			if (!member->value.IsUint64() || member->value.GetUint64() > maximum)
				throw std::invalid_argument(std::string(name) + " is out of range");
			return static_cast<std::size_t>(member->value.GetUint64());
		}

		std::string StringArgument(const rapidjson::Value& arguments, const char* name, std::string fallback = {})
		{
			const auto member = arguments.FindMember(name);
			if (member == arguments.MemberEnd())
				return fallback;
			if (!member->value.IsString())
				throw std::invalid_argument(std::string(name) + " must be a string");
			return {member->value.GetString(), member->value.GetStringLength()};
		}

		bool IsGeneratedFunctionName(std::string_view name)
		{
			return name.starts_with("sub_") || name.starts_with("j_sub_") || name.starts_with("thunk_");
		}

		void WriteMatch(rapidjson::Writer<rapidjson::StringBuffer>& writer, const Match& match)
		{
			const auto primary = HexAddress(match.primaryAddress);
			const auto secondary = HexAddress(match.secondaryAddress);
			writer.StartObject();
			writer.Key("primaryAddress");
			writer.String(primary.data(), static_cast<rapidjson::SizeType>(primary.size()));
			writer.Key("primaryName");
			writer.String(match.primaryName.data(), static_cast<rapidjson::SizeType>(match.primaryName.size()));
			writer.Key("secondaryAddress");
			writer.String(secondary.data(), static_cast<rapidjson::SizeType>(secondary.size()));
			writer.Key("secondaryName");
			writer.String(match.secondaryName.data(), static_cast<rapidjson::SizeType>(match.secondaryName.size()));
			writer.Key("similarity");
			writer.Uint(match.similarity);
			writer.Key("confidence");
			writer.Uint(match.confidence);
			writer.EndObject();
		}

#define BINJAD_DIFF_TOOL(Type, Name) \
	class Type final : public FileChildToolCall \
	{ \
	public: \
		Type() : FileChildToolCall(Name) {} \
		ipc::Reply Execute(const FileChildToolCallContext& context) const override; \
	}; \
	ipc::Reply Type::Execute(const FileChildToolCallContext& context) const

		BINJAD_DIFF_TOOL(DiffRunTool, "bn_diff_run")
		{
			{
				std::lock_guard lock(context.viewMutex);
				if (context.view->analysisActive)
					throw std::runtime_error("primary analysis is still active");
			}
			const auto json = context.diffTools.Begin(
				context.view->view, context.diff_key(), context.secondary_path(),
				[progress = context.progress](double value) {
					progress("diff", static_cast<std::size_t>(value * 1000.0), 1000);
				},
				[finished = context.finished](bool success, std::string error) {
					try
					{
						finished(success ? ipc::ANALYSIS_STATE_COMPLETE : ipc::ANALYSIS_STATE_ABORTED, error);
					}
					catch (...)
					{}
				});
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(json);
			return reply;
		};

		BINJAD_DIFF_TOOL(DiffSummaryTool, "bn_diff_summary")
		{
			const auto state = context.diffTools.Find(context.diff_key(), *context.view->view);
			const auto matches = CollectMatches(*state);
			std::unordered_set<BinaryNinja::SimilarityEntityId> matchedPrimary;
			std::unordered_set<BinaryNinja::SimilarityEntityId> matchedSecondary;
			std::size_t exactMatches = 0;
			std::uint64_t similarityTotal = 0;
			std::uint64_t confidenceTotal = 0;
			std::uint8_t minimumSimilarity = matches.empty() ? 0 : 255;
			std::uint8_t maximumSimilarity = 0;
			std::uint8_t minimumConfidence = matches.empty() ? 0 : 255;
			std::uint8_t maximumConfidence = 0;
			for (const auto& match : matches)
			{
				matchedPrimary.insert(match.primaryEntity);
				matchedSecondary.insert(match.secondaryEntity);
				if (match.similarity == 255)
					++exactMatches;
				similarityTotal += match.similarity;
				confidenceTotal += match.confidence;
				minimumSimilarity = std::min(minimumSimilarity, match.similarity);
				maximumSimilarity = std::max(maximumSimilarity, match.similarity);
				minimumConfidence = std::min(minimumConfidence, match.confidence);
				maximumConfidence = std::max(maximumConfidence, match.confidence);
			}
			std::size_t primaryUnmatched = 0;
			for (const auto entity : state->primaryNode->GetEntities())
				if (state->primaryNode->GetResults(entity).empty())
					++primaryUnmatched;
			std::size_t secondaryUnmatched = 0;
			for (const auto entity : state->secondaryNode->GetEntities())
				if (state->secondaryNode->GetResults(entity).empty())
					++secondaryUnmatched;
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("provider");
			writer.String("Google BinDiff");
			writer.Key("matches");
			writer.Uint64(matches.size());
			writer.Key("exactMatches");
			writer.Uint64(exactMatches);
			writer.Key("changedMatches");
			writer.Uint64(matches.size() - exactMatches);
			writer.Key("primaryMatched");
			writer.Uint64(matchedPrimary.size());
			writer.Key("secondaryMatched");
			writer.Uint64(matchedSecondary.size());
			writer.Key("primaryFunctions");
			writer.Uint64(state->primaryNode->GetEntities().size());
			writer.Key("secondaryFunctions");
			writer.Uint64(state->secondaryNode->GetEntities().size());
			writer.Key("primaryUnmatched");
			writer.Uint64(primaryUnmatched);
			writer.Key("secondaryUnmatched");
			writer.Uint64(secondaryUnmatched);
			writer.Key("similarity");
			writer.StartObject();
			writer.Key("minimum");
			writer.Uint(minimumSimilarity);
			writer.Key("maximum");
			writer.Uint(maximumSimilarity);
			writer.Key("average");
			writer.Double(
				matches.empty() ? 0.0 : static_cast<double>(similarityTotal) / static_cast<double>(matches.size()));
			writer.EndObject();
			writer.Key("confidence");
			writer.StartObject();
			writer.Key("minimum");
			writer.Uint(minimumConfidence);
			writer.Key("maximum");
			writer.Uint(maximumConfidence);
			writer.Key("average");
			writer.Double(
				matches.empty() ? 0.0 : static_cast<double>(confidenceTotal) / static_cast<double>(matches.size()));
			writer.EndObject();
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_DIFF_TOOL(DiffMatchListTool, "bn_diff_match_list")
		{
			const auto state = context.diffTools.Find(context.diff_key(), *context.view->view);
			auto matches = CollectMatches(*state);
			const auto query = StringArgument(context.arguments, "query");
			const auto minimumSimilarity = UnsignedArgument(context.arguments, "minSimilarity", 0, 255);
			const auto minimumConfidence = UnsignedArgument(context.arguments, "minConfidence", 0, 255);
			std::erase_if(matches, [&](const Match& match) {
				if (match.similarity < minimumSimilarity || match.confidence < minimumConfidence)
					return true;
				if (query.empty())
					return false;
				auto primaryName = Lower(match.primaryName);
				auto secondaryName = Lower(match.secondaryName);
				const auto wanted = Lower(query);
				return primaryName.find(wanted) == std::string::npos && secondaryName.find(wanted) == std::string::npos;
			});
			const auto sort = StringArgument(context.arguments, "sort", "similarity");
			const auto order = StringArgument(context.arguments, "order", "descending");
			std::ranges::sort(matches, [&](const Match& left, const Match& right) {
				const auto ascending = [&](const Match& first, const Match& second) {
					if (sort == "confidence")
						return std::tie(
								   first.confidence, first.similarity, first.primaryAddress, first.secondaryAddress)
							< std::tie(
								second.confidence, second.similarity, second.primaryAddress, second.secondaryAddress);
					if (sort == "primaryAddress")
						return std::tie(first.primaryAddress, first.secondaryAddress)
							< std::tie(second.primaryAddress, second.secondaryAddress);
					if (sort == "secondaryAddress")
						return std::tie(first.secondaryAddress, first.primaryAddress)
							< std::tie(second.secondaryAddress, second.primaryAddress);
					if (sort == "primaryName")
						return std::tie(first.primaryName, first.primaryAddress, first.secondaryAddress)
							< std::tie(second.primaryName, second.primaryAddress, second.secondaryAddress);
					if (sort == "secondaryName")
						return std::tie(first.secondaryName, first.secondaryAddress, first.primaryAddress)
							< std::tie(second.secondaryName, second.secondaryAddress, second.primaryAddress);
					return std::tie(first.similarity, first.confidence, first.primaryAddress, first.secondaryAddress)
						< std::tie(
							second.similarity, second.confidence, second.primaryAddress, second.secondaryAddress);
				};
				return order == "descending" ? ascending(right, left) : ascending(left, right);
			});
			const auto offset = std::min(
				UnsignedArgument(context.arguments, "offset", 0, std::numeric_limits<std::size_t>::max()),
				matches.size());
			const auto limit = UnsignedArgument(context.arguments, "limit", 50, 1000);
			const auto finish = offset + std::min(limit, matches.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("matches");
			writer.StartArray();
			for (std::size_t index = offset; index < finish; ++index)
				WriteMatch(writer, matches[index]);
			writer.EndArray();
			writer.Key("total");
			writer.Uint64(matches.size());
			writer.Key("nextOffset");
			if (finish < matches.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_DIFF_TOOL(DiffPrimaryUnmatchedListTool, "bn_diff_primary_unmatched_list")
		{
			const auto state = context.diffTools.Find(context.diff_key(), *context.view->view);
			std::vector<BinaryNinja::SimilarityEntityInfo> unmatched;
			for (const auto entity : state->primaryNode->GetEntities())
			{
				const auto info = state->primaryNode->GetEntity(entity);
				if (info && info->type == SimilarityEntityFunction && state->primaryNode->GetResults(entity).empty())
					unmatched.push_back(*info);
			}
			const auto query = Lower(StringArgument(context.arguments, "query"));
			if (!query.empty())
			{
				std::erase_if(unmatched, [&](const auto& info) {
					return Lower(info.name).find(query) == std::string::npos;
				});
			}
			const auto order = StringArgument(context.arguments, "order", "ascending");
			const auto sort = StringArgument(context.arguments, "sort", "address");
			std::ranges::sort(unmatched, [&](const auto& left, const auto& right) {
				const auto ascending = [&](const auto& first, const auto& second) {
					return sort == "name" ?
						std::tie(first.name, first.address) < std::tie(second.name, second.address) :
						std::tie(first.address, first.name) < std::tie(second.address, second.name);
				};
				return order == "descending" ? ascending(right, left) : ascending(left, right);
			});
			const auto offset = std::min(
				UnsignedArgument(context.arguments, "offset", 0, std::numeric_limits<std::size_t>::max()),
				unmatched.size());
			const auto limit = UnsignedArgument(context.arguments, "limit", 50, 1000);
			const auto finish = offset + std::min(limit, unmatched.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("functions");
			writer.StartArray();
			for (std::size_t index = offset; index < finish; ++index)
			{
				const auto address = HexAddress(unmatched[index].address);
				writer.StartObject();
				writer.Key("address");
				writer.String(address.data(), static_cast<rapidjson::SizeType>(address.size()));
				writer.Key("name");
				writer.String(
					unmatched[index].name.data(), static_cast<rapidjson::SizeType>(unmatched[index].name.size()));
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("total");
			writer.Uint64(unmatched.size());
			writer.Key("nextOffset");
			if (finish < unmatched.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_DIFF_TOOL(DiffSecondaryUnmatchedListTool, "bn_diff_secondary_unmatched_list")
		{
			const auto state = context.diffTools.Find(context.diff_key(), *context.view->view);
			std::vector<BinaryNinja::SimilarityEntityInfo> unmatched;
			for (const auto entity : state->secondaryNode->GetEntities())
			{
				const auto info = state->secondaryNode->GetEntity(entity);
				if (info && info->type == SimilarityEntityFunction && state->secondaryNode->GetResults(entity).empty())
					unmatched.push_back(*info);
			}
			const auto query = Lower(StringArgument(context.arguments, "query"));
			if (!query.empty())
			{
				std::erase_if(unmatched, [&](const auto& info) {
					return Lower(info.name).find(query) == std::string::npos;
				});
			}
			const auto order = StringArgument(context.arguments, "order", "ascending");
			const auto sort = StringArgument(context.arguments, "sort", "address");
			std::ranges::sort(unmatched, [&](const auto& left, const auto& right) {
				const auto ascending = [&](const auto& first, const auto& second) {
					return sort == "name" ?
						std::tie(first.name, first.address) < std::tie(second.name, second.address) :
						std::tie(first.address, first.name) < std::tie(second.address, second.name);
				};
				return order == "descending" ? ascending(right, left) : ascending(left, right);
			});
			const auto offset = std::min(
				UnsignedArgument(context.arguments, "offset", 0, std::numeric_limits<std::size_t>::max()),
				unmatched.size());
			const auto limit = UnsignedArgument(context.arguments, "limit", 50, 1000);
			const auto finish = offset + std::min(limit, unmatched.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("functions");
			writer.StartArray();
			for (std::size_t index = offset; index < finish; ++index)
			{
				const auto address = HexAddress(unmatched[index].address);
				writer.StartObject();
				writer.Key("address");
				writer.String(address.data(), static_cast<rapidjson::SizeType>(address.size()));
				writer.Key("name");
				writer.String(
					unmatched[index].name.data(), static_cast<rapidjson::SizeType>(unmatched[index].name.size()));
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("total");
			writer.Uint64(unmatched.size());
			writer.Key("nextOffset");
			if (finish < unmatched.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_DIFF_TOOL(DiffFunctionMatchesTool, "bn_diff_function_matches")
		{
			const auto state = context.diffTools.Find(context.diff_key(), *context.view->view);
			auto matches = CollectMatches(*state);
			const auto primaryAddress = DiffAddress(*state->primary, context.arguments, "primaryFunction");
			std::erase_if(matches, [&](const Match& match) { return match.primaryAddress != primaryAddress; });
			const auto query = StringArgument(context.arguments, "query");
			const auto minimumSimilarity = UnsignedArgument(context.arguments, "minSimilarity", 0, 255);
			const auto minimumConfidence = UnsignedArgument(context.arguments, "minConfidence", 0, 255);
			std::erase_if(matches, [&](const Match& match) {
				if (match.similarity < minimumSimilarity || match.confidence < minimumConfidence)
					return true;
				if (query.empty())
					return false;
				const auto wanted = Lower(query);
				return Lower(match.primaryName).find(wanted) == std::string::npos
					&& Lower(match.secondaryName).find(wanted) == std::string::npos;
			});
			const auto sort = StringArgument(context.arguments, "sort", "similarity");
			const auto order = StringArgument(context.arguments, "order", "descending");
			std::ranges::sort(matches, [&](const Match& left, const Match& right) {
				const auto ascending = [&](const Match& first, const Match& second) {
					if (sort == "confidence")
						return std::tie(
								   first.confidence, first.similarity, first.primaryAddress, first.secondaryAddress)
							< std::tie(
								second.confidence, second.similarity, second.primaryAddress, second.secondaryAddress);
					if (sort == "primaryAddress")
						return std::tie(first.primaryAddress, first.secondaryAddress)
							< std::tie(second.primaryAddress, second.secondaryAddress);
					if (sort == "secondaryAddress")
						return std::tie(first.secondaryAddress, first.primaryAddress)
							< std::tie(second.secondaryAddress, second.primaryAddress);
					if (sort == "primaryName")
						return std::tie(first.primaryName, first.primaryAddress, first.secondaryAddress)
							< std::tie(second.primaryName, second.primaryAddress, second.secondaryAddress);
					if (sort == "secondaryName")
						return std::tie(first.secondaryName, first.secondaryAddress, first.primaryAddress)
							< std::tie(second.secondaryName, second.secondaryAddress, second.primaryAddress);
					return std::tie(first.similarity, first.confidence, first.primaryAddress, first.secondaryAddress)
						< std::tie(
							second.similarity, second.confidence, second.primaryAddress, second.secondaryAddress);
				};
				return order == "descending" ? ascending(right, left) : ascending(left, right);
			});
			const auto offset = std::min(
				UnsignedArgument(context.arguments, "offset", 0, std::numeric_limits<std::size_t>::max()),
				matches.size());
			const auto limit = UnsignedArgument(context.arguments, "limit", 50, 1000);
			const auto finish = offset + std::min(limit, matches.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("matches");
			writer.StartArray();
			for (std::size_t index = offset; index < finish; ++index)
				WriteMatch(writer, matches[index]);
			writer.EndArray();
			writer.Key("total");
			writer.Uint64(matches.size());
			writer.Key("nextOffset");
			if (finish < matches.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_DIFF_TOOL(DiffMatchInfoTool, "bn_diff_match_info")
		{
			const auto state = context.diffTools.Find(context.diff_key(), *context.view->view);
			auto matches = CollectMatches(*state);
			const auto primaryAddress = DiffAddress(*state->primary, context.arguments, "primaryFunction");
			const auto secondaryAddress = DiffAddress(*state->secondary, context.arguments, "secondaryFunction");
			std::erase_if(matches, [&](const Match& match) {
				return match.primaryAddress != primaryAddress || match.secondaryAddress != secondaryAddress;
			});
			if (matches.size() != 1)
				throw std::invalid_argument(matches.empty() ? "diff match not found" : "diff match is ambiguous");
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			WriteMatch(writer, matches.front());
			return JsonReply(buffer);
		};

		BINJAD_DIFF_TOOL(DiffPortNameTool, "bn_diff_port_name_from_secondary")
		{
			const auto state = context.diffTools.Find(context.diff_key(), *context.view->view);
			auto matches = CollectMatches(*state);
			const auto primaryAddress = DiffAddress(*state->primary, context.arguments, "primaryFunction");
			const auto secondaryAddress = DiffAddress(*state->secondary, context.arguments, "secondaryFunction");
			std::erase_if(matches, [&](const Match& match) {
				return match.primaryAddress != primaryAddress || match.secondaryAddress != secondaryAddress;
			});
			if (matches.size() != 1)
				throw std::invalid_argument(matches.empty() ? "diff match not found" : "diff match is ambiguous");
			const auto& match = matches.front();
			const auto primaryFunction = state->primaryNode->GetEntityFunction(match.primaryEntity);
			const auto secondaryFunction = state->secondaryNode->GetEntityFunction(match.secondaryEntity);
			if (!primaryFunction || !secondaryFunction || !secondaryFunction->GetSymbol())
				throw std::runtime_error("matched function symbol is unavailable");
			const auto current = primaryFunction->GetSymbol();
			const auto source = secondaryFunction->GetSymbol();
			auto replacement = new BinaryNinja::Symbol(current ? current->GetType() : FunctionSymbol,
				source->GetRawName(), primaryFunction->GetStart(), current ? current->GetBinding() : GlobalBinding,
				current ? current->GetNameSpace() : BinaryNinja::NameSpace());
			state->primary->DefineUserSymbol(replacement);
			const auto applied = source->GetRawName();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("applied");
			writer.Bool(true);
			writer.Key("name");
			writer.String(applied.data(), static_cast<rapidjson::SizeType>(applied.size()));
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_DIFF_TOOL(DiffApplyTool, "bn_diff_apply_from_secondary")
		{
			const auto state = context.diffTools.Find(context.diff_key(), *context.view->view);
			auto matches = CollectMatches(*state);
			const auto primaryAddress = DiffAddress(*state->primary, context.arguments, "primaryFunction");
			const auto secondaryAddress = DiffAddress(*state->secondary, context.arguments, "secondaryFunction");
			std::erase_if(matches, [&](const Match& match) {
				return match.primaryAddress != primaryAddress || match.secondaryAddress != secondaryAddress;
			});
			if (matches.size() != 1)
				throw std::invalid_argument(matches.empty() ? "diff match not found" : "diff match is ambiguous");
			const auto& match = matches.front();
			const auto status = state->provider->Apply(*state->primaryNode, match.primaryEntity, match.result);
			if (status != SimilarityApplySuccess)
				throw std::runtime_error("Google BinDiff metadata apply failed with status "
					+ std::to_string(static_cast<unsigned>(status)));
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("applied");
			writer.Bool(true);
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_DIFF_TOOL(DiffPortNamesTool, "bn_diff_port_names_from_secondary")
		{
			const auto state = context.diffTools.Find(context.diff_key(), *context.view->view);
			const auto matches = CollectMatches(*state);
			const auto minimumSimilarity = UnsignedArgument(context.arguments, "minSimilarity", 255, 255);
			const auto minimumConfidence = UnsignedArgument(context.arguments, "minConfidence", 255, 255);
			std::unordered_map<std::uint64_t, Match> best;
			for (const auto& match : matches)
			{
				if (match.similarity < minimumSimilarity || match.confidence < minimumConfidence)
					continue;
				const auto current = best.find(match.primaryAddress);
				if (current == best.end()
					|| std::tie(match.similarity, match.confidence)
						> std::tie(current->second.similarity, current->second.confidence))
					best.insert_or_assign(match.primaryAddress, match);
			}
			std::vector<Match> selected;
			selected.reserve(best.size());
			for (const auto& [address, match] : best)
				selected.push_back(match);
			std::ranges::sort(selected, {}, &Match::primaryAddress);
			std::size_t appliedCount = 0;
			std::size_t preservedCount = 0;
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("functions");
			writer.StartArray();
			for (const auto& match : selected)
			{
				const auto primaryFunction = state->primaryNode->GetEntityFunction(match.primaryEntity);
				const auto secondaryFunction = state->secondaryNode->GetEntityFunction(match.secondaryEntity);
				const auto current = primaryFunction ? primaryFunction->GetSymbol() : nullptr;
				const auto source = secondaryFunction ? secondaryFunction->GetSymbol() : nullptr;
				const bool apply = current && current->IsAutoDefined() && IsGeneratedFunctionName(current->GetRawName())
					&& source && !source->GetRawName().empty() && !IsGeneratedFunctionName(source->GetRawName());
				if (apply)
				{
					auto replacement = new BinaryNinja::Symbol(current->GetType(), source->GetRawName(),
						match.primaryAddress, current->GetBinding(), current->GetNameSpace());
					state->primary->DefineUserSymbol(replacement);
					++appliedCount;
				}
				else
					++preservedCount;
				const auto address = HexAddress(match.primaryAddress);
				writer.StartObject();
				writer.Key("address");
				writer.String(address.data(), static_cast<rapidjson::SizeType>(address.size()));
				writer.Key("name");
				writer.String(match.secondaryName.data(), static_cast<rapidjson::SizeType>(match.secondaryName.size()));
				writer.Key("applied");
				writer.Bool(apply);
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("applied");
			writer.Uint64(appliedCount);
			writer.Key("preserved");
			writer.Uint64(preservedCount);
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_DIFF_TOOL(DiffReleaseTool, "binjad_internal_diff_release")
		{
			const auto json = context.diffTools.Release(context.diff_key());
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(json);
			return reply;
		};

#undef BINJAD_DIFF_TOOL
	}  // namespace

	void RegisterDiffingToolCalls(std::vector<std::unique_ptr<FileChildToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<DiffRunTool>());
		tools.emplace_back(std::make_unique<DiffSummaryTool>());
		tools.emplace_back(std::make_unique<DiffMatchListTool>());
		tools.emplace_back(std::make_unique<DiffPrimaryUnmatchedListTool>());
		tools.emplace_back(std::make_unique<DiffSecondaryUnmatchedListTool>());
		tools.emplace_back(std::make_unique<DiffFunctionMatchesTool>());
		tools.emplace_back(std::make_unique<DiffMatchInfoTool>());
		tools.emplace_back(std::make_unique<DiffPortNameTool>());
		tools.emplace_back(std::make_unique<DiffApplyTool>());
		tools.emplace_back(std::make_unique<DiffPortNamesTool>());
		tools.emplace_back(std::make_unique<DiffReleaseTool>());
	}
}  // namespace binjad
