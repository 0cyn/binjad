#include "../ToolCall.hpp"
#include "../ToolSchema.hpp"

#include "binjad/overseer/FileChildCoordinator.hpp"
#include "binjad/overseer/AnalysisScheduler.hpp"
#include "binjad/overseer/ProjectChildCoordinator.hpp"
#include "binjad/session/JobRegistry.hpp"
#include "binjad/session/OpenItemRegistry.hpp"

#include <chrono>
#include <filesystem>

namespace binjad::mcp {
	namespace {
		using rapidjson::StringBuffer;
		using rapidjson::Writer;

		std::string ErrorJson(std::string_view message)
		{
			StringBuffer buffer;
			Writer<StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("error");
			writer.String(message.data(), static_cast<rapidjson::SizeType>(message.size()));
			writer.EndObject();
			return {buffer.GetString(), buffer.GetSize()};
		}

		std::uint64_t CurrentUnixSeconds()
		{
			return static_cast<std::uint64_t>(
				std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
					.count());
		}

		std::string JobJson(const session::JobRecord& job)
		{
			StringBuffer buffer;
			Writer<StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("job");
			writer.String(job.reference.data(), static_cast<rapidjson::SizeType>(job.reference.size()));
			writer.Key("operation");
			writer.String(job.operation.data(), static_cast<rapidjson::SizeType>(job.operation.size()));
			writer.Key("state");
			const auto state = session::JobStateName(job.state);
			writer.String(state.data(), static_cast<rapidjson::SizeType>(state.size()));
			writer.Key("createdAt");
			writer.Uint64(job.createdAtUnix);
			writer.Key("updatedAt");
			writer.Uint64(job.updatedAtUnix);
			writer.Key("cancelRequested");
			writer.Bool(job.cancelRequested);
			if (job.analysisSession)
			{
				writer.Key("analysisSession");
				writer.String(
					job.analysisSession->data(), static_cast<rapidjson::SizeType>(job.analysisSession->size()));
			}
			if (job.binaryView)
			{
				writer.Key("binaryView");
				writer.String(job.binaryView->data(), static_cast<rapidjson::SizeType>(job.binaryView->size()));
			}
			if (job.progress)
			{
				writer.Key("progress");
				writer.StartObject();
				writer.Key("sequence");
				writer.Uint64(job.progress->sequence);
				writer.Key("timestamp");
				writer.Uint64(job.progress->timestampUnix);
				writer.Key("phase");
				writer.String(job.progress->phase.data(), static_cast<rapidjson::SizeType>(job.progress->phase.size()));
				writer.Key("completed");
				writer.Uint64(job.progress->completed);
				writer.Key("total");
				writer.Uint64(job.progress->total);
				if (!job.progress->message.empty())
				{
					writer.Key("message");
					writer.String(
						job.progress->message.data(), static_cast<rapidjson::SizeType>(job.progress->message.size()));
				}
				writer.EndObject();
			}
			if (job.state == session::JobState::Queued || job.state == session::JobState::Running)
			{
				writer.Key("pollAfterMilliseconds");
				writer.Uint(10000);
				writer.Key("nextAction");
				writer.String(
					"Call bn_job_info no more than every 10 seconds; when terminal, call bn_job_result exactly once. "
					"Avoid polling bn_analysis_status for this operation.");
			}
			writer.EndObject();
			return {buffer.GetString(), buffer.GetSize()};
		}


		struct DiffTarget
		{
			std::string primary;
			std::string secondary;
			std::optional<std::string> project;
			overseer::DiffSecondary identity;
			session::BinaryViewRecord primaryView;
		};

		std::optional<DiffTarget> ResolveDiffTarget(const ToolCallContext& context, FoundationResult& error)
		{
			if (!context.currentSession || !context.fileCoordinator || !context.openItems)
			{
				error = ToolCallSuccess(
					context, ErrorJson("analysis session, open-item, and file-child services are required"), true);
				return std::nullopt;
			}
			const auto primaryMember = context.arguments.FindMember("primary");
			const auto secondaryMember = context.arguments.FindMember("secondary");
			const std::string primary(primaryMember->value.GetString(), primaryMember->value.GetStringLength());
			const std::string secondary(secondaryMember->value.GetString(), secondaryMember->value.GetStringLength());
			std::optional<std::string> project;
			if (const auto member = context.arguments.FindMember("project"); member != context.arguments.MemberEnd())
				project.emplace(member->value.GetString(), member->value.GetStringLength());
			const auto primaryView =
				context.openItems->FindView(context.principal.id, context.currentSession->reference, primary);
			if (!primaryView || !primaryView->created)
			{
				error = ToolCallSuccess(context, ErrorJson("primary BinaryView is not materialized"), true);
				return std::nullopt;
			}
			const std::string key = project ?
				"primary:" + std::to_string(primary.size()) + ":" + primary
					+ ":project:" + std::to_string(project->size()) + ":" + *project + ":secondary:" + secondary :
				"primary:" + std::to_string(primary.size()) + ":" + primary + ":view:" + secondary;
			return DiffTarget {primary, secondary, project, {{}, key}, *primaryView};
		}

		FoundationResult ExecuteDiffTool(const ToolCallContext& context)
		{
			FoundationResult error;
			const auto target = ResolveDiffTarget(context, error);
			if (!target)
				return error;
			StringBuffer argumentsBuffer;
			Writer<StringBuffer> writer(argumentsBuffer);
			context.arguments.Accept(writer);
			const auto result = context.fileCoordinator->ExecuteDiffTool(context.principal.id,
				context.currentSession->reference, target->primary, target->identity, context.request.name,
				{argumentsBuffer.GetString(), argumentsBuffer.GetSize()});
			if (!result.value)
				return ToolCallSuccess(context, ErrorJson(result.error), true);
			return ToolCallSuccess(context, *result.value);
		}

		FoundationResult ExecuteDiffRun(const ToolCallContext& context, bool detachImmediately)
		{
			FoundationResult error;
			const auto target = ResolveDiffTarget(context, error);
			if (!target)
				return error;
			if (!context.jobs)
				return ToolCallSuccess(context, ErrorJson("job service is unavailable"), true);
			if (!target->project)
			{
				const auto secondaryView = context.openItems->FindView(
					context.principal.id, context.currentSession->reference, target->secondary);
				if (!secondaryView || !secondaryView->created)
					return ToolCallSuccess(context, ErrorJson("secondary BinaryView is not materialized"), true);
			}
			const auto owner = context.principal.id;
			const auto analysisSession = context.currentSession->reference;
			const auto openItem = target->primaryView.openItem;
			const auto created = context.jobs->Create(
				owner, analysisSession, target->primary, context.request.name, context.unixNow, context.now,
				[coordinator = context.fileCoordinator, scheduler = context.scheduler, owner, analysisSession,
					primary = target->primary, identity = target->identity, openItem] {
					if (scheduler && scheduler->CancelQueued(owner, analysisSession, openItem) != 0)
						return std::string {};
					const auto released = coordinator->ExecuteDiffTool(
						owner, analysisSession, primary, identity, "binjad_internal_diff_release");
					return released.value ? std::string {} : released.error;
				},
				detachImmediately ? Foundation::JobProgressCallback {} : context.progress);
			if (!created.job)
				return ToolCallSuccess(context, ErrorJson(created.error), true);
			const auto job = created.job->reference;
			context.jobs->Start(owner, job, context.unixNow);
			if (!detachImmediately && context.attached)
				context.attached(job, [jobs = context.jobs, owner, job] { (void)jobs->Cancel(owner, job); });
			context.jobs->ReportProgress(owner, job, "diff", 0, 1000, "staging secondary database", context.unixNow);
			const auto workerError = context.jobs->StartWorker(
				[jobs = context.jobs, coordinator = context.fileCoordinator, scheduler = context.scheduler,
					projectCoordinator = context.projectCoordinator, owner, analysisSession, primary = target->primary,
					secondary = target->secondary, project = target->project, identity = target->identity, openItem,
					job, progress = detachImmediately ? Foundation::JobProgressCallback {} : context.progress] {
					const auto cancelled = [&] {
						const auto info = jobs->Info(owner, job);
						return info.job && info.job->cancelRequested;
					};
					if (cancelled())
					{
						jobs->MarkCancelled(owner, job, ErrorJson("job cancelled"), CurrentUnixSeconds());
						return;
					}
					std::optional<overseer::AnalysisScheduler::Lease> lease;
					if (scheduler)
					{
						std::string scheduleError;
						lease = scheduler->Acquire(
							{owner, analysisSession, openItem, job},
							[coordinator, owner, analysisSession, primary](std::size_t workers) {
								(void)coordinator->SetWorkerCount(owner, analysisSession, primary, workers);
							},
							scheduleError);
						if (!lease)
						{
							jobs->MarkCancelled(owner, job, ErrorJson(scheduleError), CurrentUnixSeconds());
							return;
						}
					}
					overseer::CoordinatorResult<overseer::DiffSecondary> staged;
					if (!project)
						staged = coordinator->StageDiffView(owner, analysisSession, primary, secondary, identity.key);
					else
					{
						if (!projectCoordinator)
						{
							jobs->Fail(
								owner, job, ErrorJson("local project service is unavailable"), CurrentUnixSeconds());
							return;
						}
						auto exported = projectCoordinator->ExportFile(*project, secondary);
						if (!exported.value)
						{
							jobs->Fail(owner, job, ErrorJson(exported.error), CurrentUnixSeconds());
							return;
						}
						staged = coordinator->StageDiffFile(
							owner, analysisSession, primary, exported.value->path, identity.key);
						std::error_code ignored;
						std::filesystem::remove_all(exported.value->workingDirectory, ignored);
					}
					if (!staged.value)
					{
						jobs->Fail(owner, job, ErrorJson(staged.error), CurrentUnixSeconds());
						return;
					}
					if (cancelled())
					{
						jobs->MarkCancelled(owner, job, ErrorJson("job cancelled"), CurrentUnixSeconds());
						return;
					}
					const auto finished = coordinator->RunDiffAndWait(owner, analysisSession, primary, *staged.value,
						[jobs, owner, job, progress](const ipc::Progress& update) {
							jobs->ReportProgress(owner, job, update.phase(), update.completed(), update.total(),
								update.message(), CurrentUnixSeconds());
							if (progress)
							{
								const auto info = jobs->Info(owner, job);
								if (info.job)
									progress(*info.job);
							}
						});
					if (!finished.value || finished.value->state() != ipc::ANALYSIS_STATE_COMPLETE)
					{
						if (cancelled() || (finished.value && finished.value->state() == ipc::ANALYSIS_STATE_ABORTED))
							jobs->MarkCancelled(owner, job, ErrorJson("diff job cancelled"), CurrentUnixSeconds());
						else
							jobs->Fail(owner, job, ErrorJson(finished.value ? finished.value->error() : finished.error),
								CurrentUnixSeconds());
						return;
					}
					const auto summary =
						coordinator->ExecuteDiffTool(owner, analysisSession, primary, *staged.value, "bn_diff_summary");
					if (!summary.value)
						jobs->Fail(owner, job, ErrorJson(summary.error), CurrentUnixSeconds());
					else
						jobs->Complete(owner, job, *summary.value, CurrentUnixSeconds());
				});
			if (!workerError.empty())
				context.jobs->Fail(owner, job, ErrorJson(workerError), context.unixNow);
			if (detachImmediately)
			{
				const auto info = context.jobs->Info(owner, job);
				return info.job ?
					ToolCallSuccess(context, JobJson(*info.job)) :
					ToolCallSuccess(context, ErrorJson("job not found"), true);
			}
			const auto waited = context.jobs->WaitForTerminal(owner, job, context.config.jobs.detachAfter);
			if (!waited.job)
				return ToolCallSuccess(context, ErrorJson(waited.error), true);
			if (waited.job->state == session::JobState::Queued || waited.job->state == session::JobState::Running)
				return ToolCallSuccess(context, JobJson(*waited.job));
			const auto result = context.jobs->TakeResult(owner, job);
			if (!result.job)
				return ToolCallSuccess(context, ErrorJson(result.error), true);
			return ToolCallSuccess(context, result.job->resultJson, result.job->state != session::JobState::Complete);
		}

		FoundationResult ExecuteAttachedDiffRun(const ToolCallContext& context)
		{
			return ExecuteDiffRun(context, false);
		}

		FoundationResult ExecuteAsyncDiffRun(const ToolCallContext& context)
		{
			return ExecuteDiffRun(context, true);
		}

#define BINJAD_DIFF_TOOL(Type, Name, LegacyDescription, Handler, ...) \
	class Type final : public ToolCall \
	{ \
	public: \
		Type() : ToolCall(Name, ToolCallCategory::Diffing) {} \
		FoundationResult Execute(const ToolCallContext& context) const override { return Handler(context); } \
\
	private: \
		void WriteInputSchema(ToolCallSchemaWriter& writer) const override \
		{ \
			schema::WriteObject(writer, Name, {__VA_ARGS__}); \
		} \
	}

		BINJAD_DIFF_TOOL(DiffRunViewTool, "bn_diff_run_view",
			"Run an attached Google BinDiff comparison after saving an open secondary BinaryView to a temporary BNDB; "
			"return a terminal summary or automatically detach after the configured deadline.",
			ExecuteAttachedDiffRun,
			schema::String("primary", true, "Materialized primary BinaryView to compare and mutate."),
			schema::String(
				"secondary", true, "Materialized secondary BinaryView to save as a temporary read-only BNDB."));
		BINJAD_DIFF_TOOL(DiffRunProjectTool, "bn_diff_run_project",
			"Run an attached Google BinDiff comparison against a project-relative secondary BNDB; return a terminal "
			"summary or automatically detach after the configured deadline.",
			ExecuteAttachedDiffRun,
			schema::String("primary", true, "Materialized primary BinaryView to compare and mutate."),
			schema::String("secondary", true,
				"Secondary BinaryView reference when project is omitted, or project-relative BNDB path when project is "
				"present. Repeat the run identity exactly."),
			schema::String(
				"project", true, "Project reference used by bn_diff_run_project; omit for a bn_diff_run_view cache."));
		BINJAD_DIFF_TOOL(DiffRunViewAsyncTool, "bn_diff_run_view_async",
			"Start a Google BinDiff comparison with an open secondary BinaryView. Return its detached job immediately.",
			ExecuteAsyncDiffRun,
			schema::String("primary", true, "Materialized primary BinaryView to compare and mutate."),
			schema::String(
				"secondary", true, "Materialized secondary BinaryView to save as a temporary read-only BNDB."));
		BINJAD_DIFF_TOOL(DiffRunProjectAsyncTool, "bn_diff_run_project_async",
			"Start a Google BinDiff comparison against a project-relative secondary BNDB and return its detached job "
			"immediately.",
			ExecuteAsyncDiffRun,
			schema::String("primary", true, "Materialized primary BinaryView to compare and mutate."),
			schema::String("secondary", true,
				"Secondary BinaryView reference when project is omitted, or project-relative BNDB path when project is "
				"present. Repeat the run identity exactly."),
			schema::String(
				"project", true, "Project reference used by bn_diff_run_project; omit for a bn_diff_run_view cache."));
		BINJAD_DIFF_TOOL(DiffSummaryTool, "bn_diff_summary",
			"Summarize one cached Google BinDiff comparison with matched/unmatched counts plus exact/changed and score "
			"aggregates.",
			ExecuteDiffTool, schema::String("primary", true, "Materialized primary BinaryView to compare and mutate."),
			schema::String("secondary", true,
				"Secondary BinaryView reference when project is omitted, or project-relative BNDB path when project is "
				"present. Repeat the run identity exactly."),
			schema::NonEmptyString(
				"project", false, "Project reference used by bn_diff_run_project; omit for a bn_diff_run_view cache."));
		BINJAD_DIFF_TOOL(DiffMatchListTool, "bn_diff_match_list",
			"List cached function matches with query, metric thresholds, deterministic sorting, and pagination.",
			ExecuteDiffTool, schema::String("primary", true, "Materialized primary BinaryView to compare and mutate."),
			schema::String("secondary", true,
				"Secondary BinaryView reference when project is omitted, or project-relative BNDB path when project is "
				"present. Repeat the run identity exactly."),
			schema::NonEmptyString(
				"project", false, "Project reference used by bn_diff_run_project; omit for a bn_diff_run_view cache."),
			schema::String("query"), schema::Integer("minSimilarity", false, 0, 255, 0),
			schema::Integer("minConfidence", false, 0, 255, 0),
			schema::Enum("sort", false,
				{"similarity", "confidence", "primaryAddress", "secondaryAddress", "primaryName", "secondaryName"}),
			schema::Enum("order", false, {"ascending", "descending"}), schema::Integer("offset", false, 0, {}, 0),
			schema::Integer("limit", false, 1, 1000, 50));
		BINJAD_DIFF_TOOL(DiffPrimaryUnmatchedListTool, "bn_diff_primary_unmatched_list",
			"List unmatched primary functions with deterministic sorting and pagination.", ExecuteDiffTool,
			schema::String("primary", true, "Materialized primary BinaryView to compare and mutate."),
			schema::String("secondary", true,
				"Secondary BinaryView reference when project is omitted, or project-relative BNDB path when project is "
				"present. Repeat the run identity exactly."),
			schema::NonEmptyString(
				"project", false, "Project reference used by bn_diff_run_project; omit for a bn_diff_run_view cache."),
			schema::String("query"), schema::Enum("sort", false, {"address", "name"}),
			schema::Enum("order", false, {"ascending", "descending"}), schema::Integer("offset", false, 0, {}, 0),
			schema::Integer("limit", false, 1, 1000, 50));
		BINJAD_DIFF_TOOL(DiffSecondaryUnmatchedListTool, "bn_diff_secondary_unmatched_list",
			"List unmatched secondary functions with deterministic sorting and pagination.", ExecuteDiffTool,
			schema::String("primary", true, "Materialized primary BinaryView to compare and mutate."),
			schema::String("secondary", true,
				"Secondary BinaryView reference when project is omitted, or project-relative BNDB path when project is "
				"present. Repeat the run identity exactly."),
			schema::NonEmptyString(
				"project", false, "Project reference used by bn_diff_run_project; omit for a bn_diff_run_view cache."),
			schema::String("query"), schema::Enum("sort", false, {"address", "name"}),
			schema::Enum("order", false, {"ascending", "descending"}), schema::Integer("offset", false, 0, {}, 0),
			schema::Integer("limit", false, 1, 1000, 50));
		BINJAD_DIFF_TOOL(DiffFunctionMatchesTool, "bn_diff_function_matches",
			"List Google BinDiff matches for one primary function.", ExecuteDiffTool,
			schema::String("primary", true, "Materialized primary BinaryView to compare and mutate."),
			schema::String("secondary", true,
				"Secondary BinaryView reference when project is omitted, or project-relative BNDB path when project is "
				"present. Repeat the run identity exactly."),
			schema::NonEmptyString(
				"project", false, "Project reference used by bn_diff_run_project; omit for a bn_diff_run_view cache."),
			schema::String("primaryFunction", true), schema::String("query"),
			schema::Integer("minSimilarity", false, 0, 255, 0), schema::Integer("minConfidence", false, 0, 255, 0),
			schema::Enum("sort", false,
				{"similarity", "confidence", "primaryAddress", "secondaryAddress", "primaryName", "secondaryName"}),
			schema::Enum("order", false, {"ascending", "descending"}), schema::Integer("offset", false, 0, {}, 0),
			schema::Integer("limit", false, 1, 1000, 50));
		BINJAD_DIFF_TOOL(DiffMatchInfoTool, "bn_diff_match_info",
			"Return one exact primary-to-secondary function match.", ExecuteDiffTool,
			schema::String("primary", true, "Materialized primary BinaryView to compare and mutate."),
			schema::String("secondary", true,
				"Secondary BinaryView reference when project is omitted, or project-relative BNDB path when project is "
				"present. Repeat the run identity exactly."),
			schema::NonEmptyString(
				"project", false, "Project reference used by bn_diff_run_project; omit for a bn_diff_run_view cache."),
			schema::String("primaryFunction", true), schema::String("secondaryFunction", true));
		BINJAD_DIFF_TOOL(DiffPortNameTool, "bn_diff_port_name_from_secondary",
			"Explicitly copy one matched secondary function name onto the primary function.", ExecuteDiffTool,
			schema::String("primary", true, "Materialized primary BinaryView to compare and mutate."),
			schema::String("secondary", true,
				"Secondary BinaryView reference when project is omitted, or project-relative BNDB path when project is "
				"present. Repeat the run identity exactly."),
			schema::NonEmptyString(
				"project", false, "Project reference used by bn_diff_run_project; omit for a bn_diff_run_view cache."),
			schema::String("primaryFunction", true), schema::String("secondaryFunction", true));
		BINJAD_DIFF_TOOL(DiffApplyTool, "bn_diff_apply_from_secondary",
			"Explicitly invoke Google BinDiff's native metadata transfer for one exact match, mutating only the "
			"primary view.",
			ExecuteDiffTool, schema::String("primary", true, "Materialized primary BinaryView to compare and mutate."),
			schema::String("secondary", true,
				"Secondary BinaryView reference when project is omitted, or project-relative BNDB path when project is "
				"present. Repeat the run identity exactly."),
			schema::NonEmptyString(
				"project", false, "Project reference used by bn_diff_run_project; omit for a bn_diff_run_view cache."),
			schema::String("primaryFunction", true), schema::String("secondaryFunction", true));
		BINJAD_DIFF_TOOL(DiffPortNamesTool, "bn_diff_port_names_from_secondary",
			"Copy high-confidence secondary names onto auto-named primary functions while preserving existing primary "
			"names.",
			ExecuteDiffTool, schema::String("primary", true, "Materialized primary BinaryView to compare and mutate."),
			schema::String("secondary", true,
				"Secondary BinaryView reference when project is omitted, or project-relative BNDB path when project is "
				"present. Repeat the run identity exactly."),
			schema::String(
				"project", false, "Project reference used by bn_diff_run_project; omit for a bn_diff_run_view cache."),
			schema::Integer("minSimilarity", false, 0, 255, 255), schema::Integer("minConfidence", false, 0, 255, 255));

#undef BINJAD_DIFF_TOOL
	}  // namespace

	void RegisterDiffingTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<DiffRunViewTool>());
		tools.emplace_back(std::make_unique<DiffRunProjectTool>());
		tools.emplace_back(std::make_unique<DiffRunViewAsyncTool>());
		tools.emplace_back(std::make_unique<DiffRunProjectAsyncTool>());
		tools.emplace_back(std::make_unique<DiffSummaryTool>());
		tools.emplace_back(std::make_unique<DiffMatchListTool>());
		tools.emplace_back(std::make_unique<DiffPrimaryUnmatchedListTool>());
		tools.emplace_back(std::make_unique<DiffSecondaryUnmatchedListTool>());
		tools.emplace_back(std::make_unique<DiffFunctionMatchesTool>());
		tools.emplace_back(std::make_unique<DiffMatchInfoTool>());
		tools.emplace_back(std::make_unique<DiffPortNameTool>());
		tools.emplace_back(std::make_unique<DiffApplyTool>());
		tools.emplace_back(std::make_unique<DiffPortNamesTool>());
	}
}  // namespace binjad::mcp
