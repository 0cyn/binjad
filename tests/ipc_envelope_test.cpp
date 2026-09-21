#include "binjad/ipc/envelope.hpp"

#include <gtest/gtest.h>

TEST(IpcEnvelopeTest, RoundTripsCommand)
{
    binjad::ipc::Envelope envelope;
    envelope.set_protocol_version(binjad::ipc::kProtocolVersion);
    envelope.set_request_id(7);
    envelope.mutable_command()->mutable_set_worker_count()->set_count(4);

    const auto parsed = binjad::ipc::ParseEnvelope(binjad::ipc::SerializeEnvelope(envelope));
    EXPECT_EQ(parsed.request_id(), 7U);
    ASSERT_TRUE(parsed.has_command());
    EXPECT_EQ(parsed.command().set_worker_count().count(), 4U);
}

TEST(IpcEnvelopeTest, EnforcesEventRequestId)
{
    binjad::ipc::Envelope envelope;
    envelope.set_protocol_version(binjad::ipc::kProtocolVersion);
    envelope.set_request_id(9);
    envelope.mutable_event()->mutable_progress()->set_phase("analysis");

    const auto bytes = binjad::ipc::SerializeEnvelope(envelope);
    EXPECT_THROW(binjad::ipc::ParseEnvelope(bytes), binjad::ipc::ChannelError);
}

TEST(IpcEnvelopeTest, GeneratesNonzeroMonotonicIds)
{
    binjad::ipc::RequestIdSource source;
    EXPECT_EQ(source.Next(), 1U);
    EXPECT_EQ(source.Next(), 2U);
}
