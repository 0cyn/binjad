#include "binjad/binary_ninja/diff_tools.hpp"

#include <rapidjsonwrapper.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <unordered_set>

namespace binjad::binary_ninja
{
namespace
{
using rapidjson::Document;
using rapidjson::StringBuffer;
using rapidjson::Writer;

std::string Hex(std::uint64_t value)
{
    std::ostringstream stream;
    stream << "0x" << std::hex << value;
    return stream.str();
}

Document Arguments(std::string_view json)
{
    Document document;
    document.Parse(json.data(), json.size());
    if (document.HasParseError() || !document.IsObject())
        throw std::invalid_argument("diff tool arguments must be an object");
    return document;
}

std::uint64_t Address(BinaryNinja::BinaryView& view, const rapidjson::Value& arguments,
    const char* name)
{
    const auto member = arguments.FindMember(name);
    if (member == arguments.MemberEnd() || !member->value.IsString() ||
        member->value.GetStringLength() == 0)
        throw std::invalid_argument(std::string(name) + " must be a non-empty address expression");
    std::uint64_t address = 0;
    std::string error;
    if (!BinaryNinja::BinaryView::ParseExpression(&view,
            std::string(member->value.GetString(), member->value.GetStringLength()),
            address, 0, error))
        throw std::invalid_argument(error.empty() ? "invalid address expression" : error);
    return address;
}

std::size_t Unsigned(const rapidjson::Value& arguments, const char* name,
    std::size_t fallback, std::size_t maximum)
{
    const auto member = arguments.FindMember(name);
    if (member == arguments.MemberEnd())
        return fallback;
    if (!member->value.IsUint64() || member->value.GetUint64() > maximum)
        throw std::invalid_argument(std::string(name) + " is out of range");
    return static_cast<std::size_t>(member->value.GetUint64());
}

std::string String(const rapidjson::Value& arguments, const char* name,
    std::string fallback = {})
{
    const auto member = arguments.FindMember(name);
    if (member == arguments.MemberEnd())
        return fallback;
    if (!member->value.IsString())
        throw std::invalid_argument(std::string(name) + " must be a string");
    return {member->value.GetString(), member->value.GetStringLength()};
}

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

bool IsGeneratedFunctionName(std::string_view name)
{
    return name.starts_with("sub_") || name.starts_with("j_sub_") ||
        name.starts_with("thunk_");
}

void WriteMatch(Writer<StringBuffer>& writer, const Match& match)
{
    const auto primary = Hex(match.primaryAddress);
    const auto secondary = Hex(match.secondaryAddress);
    writer.StartObject();
    writer.Key("primaryAddress"); writer.String(primary.data(), primary.size());
    writer.Key("primaryName"); writer.String(match.primaryName.data(), match.primaryName.size());
    writer.Key("secondaryAddress"); writer.String(secondary.data(), secondary.size());
    writer.Key("secondaryName"); writer.String(match.secondaryName.data(), match.secondaryName.size());
    writer.Key("similarity"); writer.Uint(match.similarity);
    writer.Key("confidence"); writer.Uint(match.confidence);
    writer.EndObject();
}
}

struct DiffTools::State
{
    BinaryNinja::Ref<BinaryNinja::BinaryView> primary;
    BinaryNinja::Ref<BinaryNinja::BinaryView> secondary;
    BinaryNinja::Ref<BinaryNinja::FileMetadata> secondaryFile;
    BinaryNinja::Ref<BinaryNinja::SimilaritySession> session;
    BinaryNinja::Ref<BinaryNinja::SimilarityProvider> provider;
    BinaryNinja::Ref<BinaryNinja::SimilaritySessionNode> primaryNode;
    BinaryNinja::Ref<BinaryNinja::SimilaritySessionNode> secondaryNode;
    BinaryNinja::Ref<BinaryNinja::SimilaritySessionCompletion> completion;
    std::atomic<bool> finished{false};
    std::atomic<bool> succeeded{false};
    std::mutex errorMutex;
    std::string error;

    ~State()
    {
        if (completion && !completion->IsFinished())
            completion->RequestStop();
        provider = nullptr;
        session = nullptr;
        primaryNode = nullptr;
        secondaryNode = nullptr;
        secondary = nullptr;
        if (secondaryFile)
            secondaryFile->Close();
        secondaryFile = nullptr;
    }
};

DiffTools::~DiffTools()
{
    Close();
}

std::string DiffTools::Begin(BinaryNinja::Ref<BinaryNinja::BinaryView> primary,
    std::string key, const std::string& secondaryDatabase,
    ProgressCallback progress, CompletionCallback completionCallback)
{
    if (!primary)
        throw std::invalid_argument("primary BinaryView is required");
    if (key.empty())
        throw std::invalid_argument("diff cache key is required");
    if (!BNIsDatabase(secondaryDatabase.c_str()))
        throw std::invalid_argument("secondary must be an existing Binary Ninja database");
    auto providerType = BinaryNinja::SimilarityProviderType::GetByName("Google BinDiff");
    if (!providerType)
        throw std::runtime_error("Google BinDiff similarity provider is unavailable");
    auto settings = providerType->GetDefaultSettings();
    if (!settings)
        throw std::runtime_error("Google BinDiff provider settings are unavailable");
    auto provider = providerType->Create(*settings);
    if (!provider)
        throw std::runtime_error("Google BinDiff requires Binary Ninja Ultimate");

    auto secondary = BinaryNinja::Load(secondaryDatabase, false,
        R"({"analysis.database.suppressReanalysis":true})");
    if (!secondary)
        throw std::runtime_error("Binary Ninja could not open the secondary database");
    auto secondaryFile = secondary->GetFile();
    if (!secondaryFile || !secondaryFile->IsSnapshotDataAppliedWithoutError())
    {
        if (secondaryFile)
            secondaryFile->Close();
        throw std::runtime_error("secondary database analysis snapshot could not be restored");
    }

    auto state = std::make_shared<State>();
    state->primary = std::move(primary);
    state->secondary = std::move(secondary);
    state->secondaryFile = std::move(secondaryFile);
    state->provider = std::move(provider);
    state->session = new BinaryNinja::SimilaritySession();
    state->secondaryNode = new BinaryNinja::SimilaritySessionNode(state->secondary);
    state->primaryNode = new BinaryNinja::SimilaritySessionNode(state->primary);
    state->session->AddProvider(state->provider);
    auto graph = state->session->GetGraph();
    graph->AddNode(state->secondaryNode);
    graph->AddNode(state->primaryNode);
    if (!graph->AddEdge(*state->secondaryNode, *state->primaryNode))
        throw std::runtime_error("cannot create secondary-to-primary similarity edge");
    state->completion = state->session->Run();
    if (!state->completion)
        throw std::runtime_error("Google BinDiff session did not start");

    std::shared_ptr<State> replaced;
    {
        std::lock_guard lock(mutex_);
        if (const auto existing = states_.find(key); existing != states_.end())
            replaced = existing->second;
        states_.insert_or_assign(key, state);
        workers_.emplace_back([state, progress = std::move(progress),
            completionCallback = std::move(completionCallback)] {
            while (!state->completion->IsFinished())
            {
                if (progress)
                    progress(state->completion->GetProgress(
                        BinaryNinja::SimilaritySessionCompletionQuery::ForSession()));
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            const bool stopped = state->completion->IsStopRequested();
            state->succeeded = !stopped;
            state->finished = true;
            if (progress)
                progress(1.0);
            if (completionCallback)
                completionCallback(!stopped, stopped ? "diff run stopped" : std::string{});
        });
    }
    if (replaced && replaced->completion && !replaced->completion->IsFinished())
        replaced->completion->RequestStop();
    return R"({"state":"running","provider":"Google BinDiff"})";
}

std::shared_ptr<DiffTools::State> DiffTools::Find(
    std::string_view key, BinaryNinja::BinaryView& primary) const
{
    std::lock_guard lock(mutex_);
    const auto found = states_.find(std::string(key));
    if (found == states_.end())
        throw std::runtime_error("diff cache not found; run the comparison first");
    if (found->second->primary.GetPtr() != &primary)
        throw std::runtime_error("diff cache belongs to a different primary BinaryView");
    if (!found->second->finished)
        throw std::runtime_error("diff comparison is still running");
    if (!found->second->succeeded)
        throw std::runtime_error("diff comparison did not complete successfully");
    return found->second;
}

std::string DiffTools::Release(std::string_view key)
{
    std::shared_ptr<State> state;
    {
        std::lock_guard lock(mutex_);
        const auto found = states_.find(std::string(key));
        if (found == states_.end())
            return R"({"released":false})";
        state = std::move(found->second);
        states_.erase(found);
    }
    if (state->completion && !state->completion->IsFinished())
        state->completion->RequestStop();
    return R"({"released":true})";
}

std::string DiffTools::Execute(std::string_view name,
    BinaryNinja::Ref<BinaryNinja::BinaryView> primary,
    std::string_view key, std::string_view argumentsJson)
{
    if (name == "binjad_internal_diff_release")
        return Release(key);
    auto state = Find(key, *primary);
    auto arguments = Arguments(argumentsJson);

    std::vector<Match> matches;
    for (const auto primaryEntity : state->primaryNode->GetEntities())
    {
        const auto primaryInfo = state->primaryNode->GetEntity(primaryEntity);
        if (!primaryInfo || primaryInfo->type != SimilarityEntityFunction)
            continue;
        for (const auto resultId : state->primaryNode->GetResults(primaryEntity))
        {
            const auto result = state->primaryNode->GetResult(resultId);
            if (!result || result->providerId != state->provider->GetId() ||
                result->target.nodeId != state->secondaryNode->GetId())
                continue;
            const auto secondaryInfo = state->secondaryNode->GetEntity(result->target.entityId);
            if (!secondaryInfo)
                continue;
            matches.push_back({primaryEntity, result->target.entityId, resultId,
                primaryInfo->address, secondaryInfo->address, primaryInfo->name,
                secondaryInfo->name, result->similarity, result->confidence});
        }
    }

    if (name == "bn_diff_summary")
    {
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
            if (match.similarity == 255) ++exactMatches;
            similarityTotal += match.similarity;
            confidenceTotal += match.confidence;
            minimumSimilarity = std::min(minimumSimilarity, match.similarity);
            maximumSimilarity = std::max(maximumSimilarity, match.similarity);
            minimumConfidence = std::min(minimumConfidence, match.confidence);
            maximumConfidence = std::max(maximumConfidence, match.confidence);
        }
        std::size_t primaryUnmatched = 0;
        for (const auto entity : state->primaryNode->GetEntities())
            if (state->primaryNode->GetResults(entity).empty()) ++primaryUnmatched;
        std::size_t secondaryUnmatched = 0;
        for (const auto entity : state->secondaryNode->GetEntities())
            if (state->secondaryNode->GetResults(entity).empty()) ++secondaryUnmatched;
        StringBuffer buffer; Writer<StringBuffer> writer(buffer); writer.StartObject();
        writer.Key("provider"); writer.String("Google BinDiff");
        writer.Key("matches"); writer.Uint64(matches.size());
        writer.Key("exactMatches"); writer.Uint64(exactMatches);
        writer.Key("changedMatches"); writer.Uint64(matches.size() - exactMatches);
        writer.Key("primaryMatched"); writer.Uint64(matchedPrimary.size());
        writer.Key("secondaryMatched"); writer.Uint64(matchedSecondary.size());
        writer.Key("primaryFunctions"); writer.Uint64(state->primaryNode->GetEntities().size());
        writer.Key("secondaryFunctions"); writer.Uint64(state->secondaryNode->GetEntities().size());
        writer.Key("primaryUnmatched"); writer.Uint64(primaryUnmatched);
        writer.Key("secondaryUnmatched"); writer.Uint64(secondaryUnmatched);
        writer.Key("similarity"); writer.StartObject();
        writer.Key("minimum"); writer.Uint(minimumSimilarity);
        writer.Key("maximum"); writer.Uint(maximumSimilarity);
        writer.Key("average"); writer.Double(matches.empty() ? 0.0 :
            static_cast<double>(similarityTotal) / static_cast<double>(matches.size()));
        writer.EndObject();
        writer.Key("confidence"); writer.StartObject();
        writer.Key("minimum"); writer.Uint(minimumConfidence);
        writer.Key("maximum"); writer.Uint(maximumConfidence);
        writer.Key("average"); writer.Double(matches.empty() ? 0.0 :
            static_cast<double>(confidenceTotal) / static_cast<double>(matches.size()));
        writer.EndObject();
        writer.EndObject(); return {buffer.GetString(), buffer.GetSize()};
    }

    if (name == "bn_diff_primary_unmatched_list" || name == "bn_diff_secondary_unmatched_list")
    {
        auto node = name == "bn_diff_primary_unmatched_list" ? state->primaryNode : state->secondaryNode;
        std::vector<BinaryNinja::SimilarityEntityInfo> unmatched;
        for (const auto entity : node->GetEntities())
        {
            const auto info = node->GetEntity(entity);
            if (info && info->type == SimilarityEntityFunction && node->GetResults(entity).empty())
                unmatched.push_back(*info);
        }
        auto query = String(arguments, "query");
        std::ranges::transform(query, query.begin(), [](unsigned char c) { return std::tolower(c); });
        if (!query.empty())
        {
            std::erase_if(unmatched, [&](const auto& info) {
                auto name = info.name;
                std::ranges::transform(name, name.begin(), [](unsigned char c) { return std::tolower(c); });
                return name.find(query) == std::string::npos;
            });
        }
        const auto order = String(arguments, "order", "ascending");
        const auto sort = String(arguments, "sort", "address");
        std::ranges::sort(unmatched, [&](const auto& left, const auto& right) {
            const auto ascending = [&](const auto& first, const auto& second) {
                return sort == "name"
                    ? std::tie(first.name, first.address) < std::tie(second.name, second.address)
                    : std::tie(first.address, first.name) < std::tie(second.address, second.name);
            };
            return order == "descending" ? ascending(right, left) : ascending(left, right);
        });
        const auto offset = std::min(Unsigned(arguments, "offset", 0, SIZE_MAX), unmatched.size());
        const auto limit = Unsigned(arguments, "limit", 50, 1000);
        const auto finish = offset + std::min(limit, unmatched.size() - offset);
        StringBuffer buffer; Writer<StringBuffer> writer(buffer); writer.StartObject();
        writer.Key("functions"); writer.StartArray();
        for (std::size_t i = offset; i < finish; ++i)
        {
            const auto address = Hex(unmatched[i].address); writer.StartObject();
            writer.Key("address"); writer.String(address.data(), address.size());
            writer.Key("name"); writer.String(unmatched[i].name.data(), unmatched[i].name.size());
            writer.EndObject();
        }
        writer.EndArray(); writer.Key("total"); writer.Uint64(unmatched.size());
        writer.Key("nextOffset"); if (finish < unmatched.size()) writer.Uint64(finish); else writer.Null();
        writer.EndObject(); return {buffer.GetString(), buffer.GetSize()};
    }

    if (name == "bn_diff_function_matches" || name == "bn_diff_match_info" ||
        name == "bn_diff_port_name_from_secondary" || name == "bn_diff_apply_from_secondary")
    {
        const auto primaryAddress = Address(*state->primary, arguments, "primaryFunction");
        std::erase_if(matches, [&](const Match& match) { return match.primaryAddress != primaryAddress; });
        if (name != "bn_diff_function_matches")
        {
            const auto secondaryAddress = Address(*state->secondary, arguments, "secondaryFunction");
            std::erase_if(matches, [&](const Match& match) { return match.secondaryAddress != secondaryAddress; });
            if (matches.size() != 1)
                throw std::invalid_argument(matches.empty() ? "diff match not found" : "diff match is ambiguous");
            const auto& match = matches.front();
            if (name == "bn_diff_match_info")
            {
                StringBuffer buffer; Writer<StringBuffer> writer(buffer); WriteMatch(writer, match);
                return {buffer.GetString(), buffer.GetSize()};
            }
            if (name == "bn_diff_apply_from_secondary")
            {
                const auto status = state->provider->Apply(
                    *state->primaryNode, match.primaryEntity, match.result);
                if (status != SimilarityApplySuccess)
                    throw std::runtime_error("Google BinDiff metadata apply failed with status " +
                        std::to_string(static_cast<unsigned>(status)));
                return R"({"applied":true})";
            }
            const auto primaryFunction = state->primaryNode->GetEntityFunction(match.primaryEntity);
            const auto secondaryFunction = state->secondaryNode->GetEntityFunction(match.secondaryEntity);
            if (!primaryFunction || !secondaryFunction || !secondaryFunction->GetSymbol())
                throw std::runtime_error("matched function symbol is unavailable");
            const auto current = primaryFunction->GetSymbol();
            const auto source = secondaryFunction->GetSymbol();
            auto replacement = new BinaryNinja::Symbol(current ? current->GetType() : FunctionSymbol,
                source->GetRawName(), primaryFunction->GetStart(),
                current ? current->GetBinding() : GlobalBinding,
                current ? current->GetNameSpace() : BinaryNinja::NameSpace());
            state->primary->DefineUserSymbol(replacement);
            StringBuffer buffer; Writer<StringBuffer> writer(buffer); writer.StartObject();
            writer.Key("applied"); writer.Bool(true); writer.Key("name");
            const auto applied = source->GetRawName(); writer.String(applied.data(), applied.size());
            writer.EndObject(); return {buffer.GetString(), buffer.GetSize()};
        }
    }

    if (name == "bn_diff_port_names_from_secondary")
    {
        const auto minimumSimilarity = Unsigned(arguments, "minSimilarity", 255, 255);
        const auto minimumConfidence = Unsigned(arguments, "minConfidence", 255, 255);
        std::unordered_map<std::uint64_t, Match> best;
        for (const auto& match : matches)
        {
            if (match.similarity < minimumSimilarity || match.confidence < minimumConfidence)
                continue;
            const auto current = best.find(match.primaryAddress);
            if (current == best.end() || std::tie(match.similarity, match.confidence) >
                    std::tie(current->second.similarity, current->second.confidence))
                best.insert_or_assign(match.primaryAddress, match);
        }
        std::vector<Match> selected;
        selected.reserve(best.size());
        for (const auto& [address, match] : best)
            selected.push_back(match);
        std::ranges::sort(selected, {}, &Match::primaryAddress);
        std::size_t appliedCount = 0, preservedCount = 0;
        StringBuffer buffer; Writer<StringBuffer> writer(buffer); writer.StartObject();
        writer.Key("functions"); writer.StartArray();
        for (const auto& match : selected)
        {
            const auto address = match.primaryAddress;
            const auto primaryFunction = state->primaryNode->GetEntityFunction(match.primaryEntity);
            const auto secondaryFunction = state->secondaryNode->GetEntityFunction(match.secondaryEntity);
            const auto current = primaryFunction ? primaryFunction->GetSymbol() : nullptr;
            const auto source = secondaryFunction ? secondaryFunction->GetSymbol() : nullptr;
            const bool apply = current && current->IsAutoDefined() &&
                IsGeneratedFunctionName(current->GetRawName()) && source &&
                !source->GetRawName().empty() &&
                !IsGeneratedFunctionName(source->GetRawName());
            if (apply)
            {
                auto replacement = new BinaryNinja::Symbol(current->GetType(), source->GetRawName(),
                    address, current->GetBinding(), current->GetNameSpace());
                state->primary->DefineUserSymbol(replacement); ++appliedCount;
            }
            else ++preservedCount;
            writer.StartObject(); const auto addressText = Hex(address);
            writer.Key("address"); writer.String(addressText.data(), addressText.size());
            writer.Key("name"); writer.String(match.secondaryName.data(), match.secondaryName.size());
            writer.Key("applied"); writer.Bool(apply); writer.EndObject();
        }
        writer.EndArray(); writer.Key("applied"); writer.Uint64(appliedCount);
        writer.Key("preserved"); writer.Uint64(preservedCount); writer.EndObject();
        return {buffer.GetString(), buffer.GetSize()};
    }

    const auto query = String(arguments, "query");
    const auto minimumSimilarity = Unsigned(arguments, "minSimilarity", 0, 255);
    const auto minimumConfidence = Unsigned(arguments, "minConfidence", 0, 255);
    std::erase_if(matches, [&](const Match& match) {
        if (match.similarity < minimumSimilarity || match.confidence < minimumConfidence)
            return true;
        if (query.empty()) return false;
        auto primaryName = match.primaryName, secondaryName = match.secondaryName, wanted = query;
        std::ranges::transform(primaryName, primaryName.begin(), [](unsigned char c) { return std::tolower(c); });
        std::ranges::transform(secondaryName, secondaryName.begin(), [](unsigned char c) { return std::tolower(c); });
        std::ranges::transform(wanted, wanted.begin(), [](unsigned char c) { return std::tolower(c); });
        return primaryName.find(wanted) == std::string::npos && secondaryName.find(wanted) == std::string::npos;
    });
    const auto sort = String(arguments, "sort", "similarity");
    const auto order = String(arguments, "order", "descending");
    std::ranges::sort(matches, [&](const Match& left, const Match& right) {
        const auto ascending = [&](const Match& first, const Match& second) {
            if (sort == "confidence") return std::tie(first.confidence, first.similarity, first.primaryAddress,
                first.secondaryAddress) < std::tie(second.confidence, second.similarity, second.primaryAddress,
                second.secondaryAddress);
            if (sort == "primaryAddress") return std::tie(first.primaryAddress, first.secondaryAddress) <
                std::tie(second.primaryAddress, second.secondaryAddress);
            if (sort == "secondaryAddress") return std::tie(first.secondaryAddress, first.primaryAddress) <
                std::tie(second.secondaryAddress, second.primaryAddress);
            if (sort == "primaryName") return std::tie(first.primaryName, first.primaryAddress,
                first.secondaryAddress) < std::tie(second.primaryName, second.primaryAddress,
                second.secondaryAddress);
            if (sort == "secondaryName") return std::tie(first.secondaryName, first.secondaryAddress,
                first.primaryAddress) < std::tie(second.secondaryName, second.secondaryAddress,
                second.primaryAddress);
            return std::tie(first.similarity, first.confidence, first.primaryAddress,
                first.secondaryAddress) < std::tie(second.similarity, second.confidence,
                second.primaryAddress, second.secondaryAddress);
        };
        return order == "descending" ? ascending(right, left) : ascending(left, right);
    });
    const auto offset = std::min(Unsigned(arguments, "offset", 0, SIZE_MAX), matches.size());
    const auto limit = Unsigned(arguments, "limit", 50, 1000);
    const auto finish = offset + std::min(limit, matches.size() - offset);
    StringBuffer buffer; Writer<StringBuffer> writer(buffer); writer.StartObject();
    writer.Key("matches"); writer.StartArray();
    for (std::size_t i = offset; i < finish; ++i) WriteMatch(writer, matches[i]);
    writer.EndArray(); writer.Key("total"); writer.Uint64(matches.size());
    writer.Key("nextOffset"); if (finish < matches.size()) writer.Uint64(finish); else writer.Null();
    writer.EndObject(); return {buffer.GetString(), buffer.GetSize()};
}

void DiffTools::Close() noexcept
{
    std::vector<std::shared_ptr<State>> states;
    {
        std::lock_guard lock(mutex_);
        for (auto& [key, state] : states_)
            states.push_back(std::move(state));
        states_.clear();
    }
    for (const auto& state : states)
        if (state->completion && !state->completion->IsFinished())
            state->completion->RequestStop();
    for (auto& worker : workers_)
        if (worker.joinable()) worker.join();
    workers_.clear();
}
}
