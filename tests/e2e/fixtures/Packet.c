/* Freestanding packet dispatcher, compiled for three real executable formats.
 * The tests know its behavior and data, not its compiler's instruction layout. */
typedef unsigned char u8;
typedef unsigned int u32;

#if defined(_WIN32)
	#define EXPORTED __declspec(dllexport)
#else
	#define EXPORTED __attribute__((visibility("default")))
#endif
#define NOINLINE __attribute__((noinline))

struct Packet
{
	u32 opcode;
	u32 length;
	const u8* payload;
};

EXPORTED const char banner[] = "BINJAD-PACKET/v1 caf\xc3\xa9 \xe6\x97\xa5\xe6\x9c\xac";
EXPORTED const char denied[] = "packet rejected: invalid length";
EXPORTED volatile u32 observed;

EXPORTED NOINLINE u32 packet_checksum(const u8* payload, u32 length)
{
	u32 value = 0x13579bdf;
	for (u32 i = 0; i < length; ++i)
		value = (value << 5) ^ (value >> 27) ^ payload[i];
	return value;
}

EXPORTED NOINLINE int packet_dispatch(const struct Packet* packet)
{
	if (!packet || packet->length > 64 || !packet->payload)
		return -7;
	switch (packet->opcode)
	{
	case 1:
		return (int)packet_checksum(packet->payload, packet->length);
	case 2:
		return (int)packet->length + banner[0];
	case 3:
		return denied[packet->length % (sizeof(denied) - 1)];
	default:
		return -9;
	}
}

EXPORTED NOINLINE int main(void)
{
	const struct Packet packet = {1, sizeof(banner) - 1, (const u8*)banner};
	observed = (u32)packet_dispatch(&packet);
	return (int)(observed & 255);
}
