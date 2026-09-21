#pragma once

#include "binjad/Config.hpp"
#include "binjad/platform/Cpu.hpp"

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace binjad::overseer {
	struct AnalysisScheduleRequest
	{
		std::string token;
		std::string analysisSession;
		std::string file;
		std::string job;
	};

	struct AnalysisSchedulerStatus
	{
		std::size_t logicalCpuCount = 0;
		std::size_t workerBudget = 0;
		std::size_t allocatedWorkers = 0;
		std::size_t activeAnalyses = 0;
		std::size_t queuedAnalyses = 0;
	};

	class AnalysisScheduler
	{
	public:
		using Capacity = std::function<platform::CpuCapacityResult()>;
		using AllocationCallback = std::function<void(std::size_t)>;

		class Lease
		{
		public:
			Lease() = default;
			Lease(const Lease&) = delete;
			Lease& operator=(const Lease&) = delete;
			Lease(Lease&& other) noexcept;
			Lease& operator=(Lease&& other) noexcept;
			~Lease();

			explicit operator bool() const { return scheduler_ != nullptr; }
			std::size_t Workers() const;

		private:
			friend class AnalysisScheduler;
			Lease(AnalysisScheduler* scheduler, std::uint64_t id);
			void Reset();

			AnalysisScheduler* scheduler_ = nullptr;
			std::uint64_t id_ = 0;
		};

		explicit AnalysisScheduler(CpuConfig config, Capacity capacity = {});
		AnalysisScheduler(const AnalysisScheduler&) = delete;
		AnalysisScheduler& operator=(const AnalysisScheduler&) = delete;
		~AnalysisScheduler();

		std::optional<Lease> Acquire(
			AnalysisScheduleRequest request, AllocationCallback allocation, std::string& error);
		bool Cancel(std::uint64_t id);
		std::size_t CancelQueued(std::string_view token, std::string_view analysisSession, std::string_view file);
		AnalysisSchedulerStatus Status() const;

	private:
		struct Entry;
		struct AllocationAction;

		std::string UnitKey(const Entry& entry) const;
		std::vector<AllocationAction> RebalanceLocked();
		static void RunActions(std::vector<AllocationAction> actions);
		void Release(std::uint64_t id);
		std::size_t Workers(std::uint64_t id) const;

		CpuConfig config_;
		Capacity capacity_;
		std::unordered_map<std::uint64_t, std::shared_ptr<Entry>> entries_;
		std::uint64_t nextId_ = 1;
		std::uint64_t nextSequence_ = 1;
		std::size_t rotation_ = 0;
		AnalysisSchedulerStatus status_;
		bool shuttingDown_ = false;
		mutable std::mutex mutex_;
	};
}  // namespace binjad::overseer
