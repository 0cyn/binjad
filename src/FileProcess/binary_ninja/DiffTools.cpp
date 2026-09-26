#include "binjad/binary_ninja/DiffTools.hpp"

#include <chrono>
#include <stdexcept>

namespace binjad::binary_ninja {
	DiffTools::State::~State()
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

	DiffTools::~DiffTools()
	{
		Close();
	}

	std::string DiffTools::Begin(BinaryNinja::Ref<BinaryNinja::BinaryView> primary, std::string key,
		const std::string& secondaryDatabase, ProgressCallback progress, CompletionCallback completionCallback)
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

		auto secondary =
			BinaryNinja::Load(secondaryDatabase, false, R"({"analysis.database.suppressReanalysis":true})");
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
			workers_.emplace_back(
				[state, progress = std::move(progress), completionCallback = std::move(completionCallback)] {
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
						completionCallback(!stopped, stopped ? "diff run stopped" : std::string {});
				});
		}
		if (replaced && replaced->completion && !replaced->completion->IsFinished())
			replaced->completion->RequestStop();
		return R"({"state":"running","provider":"Google BinDiff"})";
	}

	std::shared_ptr<DiffTools::State> DiffTools::Find(std::string_view key, BinaryNinja::BinaryView& primary) const
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
			if (worker.joinable())
				worker.join();
		workers_.clear();
	}
}  // namespace binjad::binary_ninja
