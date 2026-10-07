#include "../FileChild.hpp"
#include "../ToolCall.hpp"
#include "../ToolSupport.hpp"

#include <view/elf/elfview.h>

#include <algorithm>
#include <array>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>

namespace binjad {
	using namespace file_process;

	namespace {
		constexpr std::size_t kMaximumHeaderRows = 65536;

		class ViewReader
		{
		public:
			explicit ViewReader(BinaryNinja::BinaryView* view, bool littleEndian = true) :
				view_(view), little_(littleEndian)
			{}

			void SetLittleEndian(bool value) { little_ = value; }

			std::vector<std::uint8_t> Bytes(std::uint64_t address, std::size_t size) const
			{
				std::vector<std::uint8_t> result(size);
				if (size != 0 && view_->Read(result.data(), address, size) != size)
					throw std::runtime_error("file header is truncated or not mapped");
				return result;
			}

			std::uint8_t U8(std::uint64_t address) const { return Bytes(address, 1)[0]; }

			std::uint16_t U16(std::uint64_t address) const
			{
				const auto bytes = Bytes(address, 2);
				return little_ ?
					static_cast<std::uint16_t>(bytes[0] | (bytes[1] << 8)) :
					static_cast<std::uint16_t>((bytes[0] << 8) | bytes[1]);
			}

			std::uint32_t U32(std::uint64_t address) const
			{
				const auto bytes = Bytes(address, 4);
				std::uint32_t value = 0;
				if (little_)
					for (std::size_t index = 0; index < 4; ++index)
						value |= std::uint32_t(bytes[index]) << (index * 8);
				else
					for (const auto byte : bytes)
						value = (value << 8) | byte;
				return value;
			}

			std::uint64_t U64(std::uint64_t address) const
			{
				const auto bytes = Bytes(address, 8);
				std::uint64_t value = 0;
				if (little_)
					for (std::size_t index = 0; index < 8; ++index)
						value |= std::uint64_t(bytes[index]) << (index * 8);
				else
					for (const auto byte : bytes)
						value = (value << 8) | byte;
				return value;
			}

			std::string CString(std::uint64_t address, std::size_t maximum = 4096) const
			{
				std::string result;
				result.reserve(std::min<std::size_t>(maximum, 128));
				for (std::size_t index = 0; index < maximum; ++index)
				{
					const auto value = U8(address + index);
					if (value == 0)
						return result;
					result.push_back(static_cast<char>(value));
				}
				throw std::runtime_error("header string is not terminated within its containing structure");
			}

			std::string FixedString(std::uint64_t address, std::size_t size) const
			{
				const auto bytes = Bytes(address, size);
				const auto end = std::find(bytes.begin(), bytes.end(), 0);
				return {bytes.begin(), end};
			}

		private:
			BinaryNinja::BinaryView* view_;
			bool little_;
		};

		std::uint64_t HeaderAddress(BinaryNinja::BinaryView* view, std::string_view symbol)
		{
			if (const auto found = view->GetSymbolByRawName(std::string(symbol)))
				return found->GetAddress();
			return view->GetImageBase();
		}

		std::string HexBytes(std::span<const std::uint8_t> bytes)
		{
			std::ostringstream stream;
			stream << std::hex << std::setfill('0');
			for (const auto byte : bytes)
				stream << std::setw(2) << static_cast<unsigned>(byte);
			return stream.str();
		}

		std::string Uuid(std::span<const std::uint8_t> bytes)
		{
			if (bytes.size() != 16)
				return {};
			const auto raw = HexBytes(bytes);
			return raw.substr(0, 8) + '-' + raw.substr(8, 4) + '-' + raw.substr(12, 4) + '-' + raw.substr(16, 4) + '-'
				+ raw.substr(20, 12);
		}

		std::string PackedVersion(std::uint32_t value)
		{
			return std::to_string(value >> 16) + '.' + std::to_string((value >> 8) & 0xff) + '.'
				+ std::to_string(value & 0xff);
		}

		struct ListArguments
		{
			std::string query;
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
		};

		ListArguments ParseListArguments(const rapidjson::Value& arguments)
		{
			ListArguments result;
			if (const auto value = arguments.FindMember("query"); value != arguments.MemberEnd())
				result.query = Lower({value->value.GetString(), value->value.GetStringLength()});
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				result.offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				result.limit = static_cast<std::size_t>(value->value.GetUint64());
			return result;
		}

		template <typename WriterType>
		void WriteText(WriterType& writer, std::string_view key, std::string_view value)
		{
			writer.Key(key.data(), static_cast<rapidjson::SizeType>(key.size()));
			writer.String(value.data(), static_cast<rapidjson::SizeType>(value.size()));
		}

		template <typename WriteBody>
		ipc::Reply JsonReply(WriteBody writeBody)
		{
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writeBody(writer);
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		}

		struct MachHeader
		{
			std::uint64_t address = 0;
			bool little = true;
			bool is64 = false;
			std::uint32_t cpuType = 0;
			std::uint32_t cpuSubtype = 0;
			std::uint32_t fileType = 0;
			std::uint32_t commandCount = 0;
			std::uint32_t commandBytes = 0;
			std::uint32_t flags = 0;
			std::uint64_t commands = 0;
		};

		MachHeader ParseMachHeader(BinaryNinja::BinaryView* view)
		{
			MachHeader result;
			result.address = HeaderAddress(view, "__macho_header");
			ViewReader reader(view);
			const auto magic = reader.U32(result.address);
			if (magic == 0xfeedface || magic == 0xfeedfacf)
			{
				result.little = true;
				result.is64 = magic == 0xfeedfacf;
			}
			else if (magic == 0xcefaedfe || magic == 0xcffaedfe)
			{
				result.little = false;
				result.is64 = magic == 0xcffaedfe;
			}
			else
				throw std::runtime_error("BinaryView does not contain a mapped Mach-O header");
			reader.SetLittleEndian(result.little);
			result.cpuType = reader.U32(result.address + 4);
			result.cpuSubtype = reader.U32(result.address + 8);
			result.fileType = reader.U32(result.address + 12);
			result.commandCount = reader.U32(result.address + 16);
			result.commandBytes = reader.U32(result.address + 20);
			result.flags = reader.U32(result.address + 24);
			result.commands = result.address + (result.is64 ? 32 : 28);
			if (result.commandCount > kMaximumHeaderRows || result.commandBytes > 256 * 1024 * 1024)
				throw std::runtime_error("Mach-O load-command bounds are unreasonable");
			return result;
		}

		struct MachCommand
		{
			std::size_t index = 0;
			std::uint64_t address = 0;
			std::uint32_t command = 0;
			std::uint32_t size = 0;
		};

		std::vector<MachCommand> MachCommands(BinaryNinja::BinaryView* view, const MachHeader& header)
		{
			ViewReader reader(view, header.little);
			std::vector<MachCommand> result;
			result.reserve(header.commandCount);
			std::uint64_t address = header.commands;
			std::uint64_t consumed = 0;
			for (std::size_t index = 0; index < header.commandCount; ++index)
			{
				const auto command = reader.U32(address);
				const auto size = reader.U32(address + 4);
				if (size < 8 || size > header.commandBytes - consumed)
					throw std::runtime_error("Mach-O load command has an invalid size");
				result.push_back({index, address, command, size});
				address += size;
				consumed += size;
			}
			return result;
		}

		std::string_view MachCommandName(std::uint32_t command)
		{
			switch (command)
			{
			case 0x1:
				return "LC_SEGMENT";
			case 0x2:
				return "LC_SYMTAB";
			case 0x5:
				return "LC_UNIXTHREAD";
			case 0xc:
				return "LC_LOAD_DYLIB";
			case 0xd:
				return "LC_ID_DYLIB";
			case 0xe:
				return "LC_LOAD_DYLINKER";
			case 0xf:
				return "LC_ID_DYLINKER";
			case 0x19:
				return "LC_SEGMENT_64";
			case 0x1b:
				return "LC_UUID";
			case 0x1d:
				return "LC_CODE_SIGNATURE";
			case 0x21:
				return "LC_ENCRYPTION_INFO";
			case 0x20:
				return "LC_LAZY_LOAD_DYLIB";
			case 0x22:
				return "LC_DYLD_INFO";
			case 0x24:
				return "LC_VERSION_MIN_MACOSX";
			case 0x25:
				return "LC_VERSION_MIN_IPHONEOS";
			case 0x26:
				return "LC_FUNCTION_STARTS";
			case 0x29:
				return "LC_DATA_IN_CODE";
			case 0x2a:
				return "LC_SOURCE_VERSION";
			case 0x2c:
				return "LC_ENCRYPTION_INFO_64";
			case 0x2f:
				return "LC_VERSION_MIN_TVOS";
			case 0x30:
				return "LC_VERSION_MIN_WATCHOS";
			case 0x32:
				return "LC_BUILD_VERSION";
			case 0x33:
				return "LC_DYLD_EXPORTS_TRIE";
			case 0x34:
				return "LC_DYLD_CHAINED_FIXUPS";
			case 0x80000018:
				return "LC_LOAD_WEAK_DYLIB";
			case 0x8000001c:
				return "LC_RPATH";
			case 0x8000001f:
				return "LC_REEXPORT_DYLIB";
			case 0x80000022:
				return "LC_DYLD_INFO_ONLY";
			case 0x80000023:
				return "LC_LOAD_UPWARD_DYLIB";
			case 0x80000028:
				return "LC_MAIN";
			default:
				return "UNKNOWN";
			}
		}

		bool IsMachDylibCommand(std::uint32_t command)
		{
			return command == 0xc || command == 0xd || command == 0x20 || command == 0x80000018 || command == 0x8000001f
				|| command == 0x80000023;
		}

		std::string MachCommandString(
			BinaryNinja::BinaryView* view, const MachHeader& header, const MachCommand& command)
		{
			ViewReader reader(view, header.little);
			const auto stringOffset = reader.U32(command.address + 8);
			if (stringOffset < 8 || stringOffset >= command.size)
				throw std::runtime_error("Mach-O load command contains an invalid string offset");
			return reader.CString(command.address + stringOffset, command.size - stringOffset);
		}

		std::string_view MachFileType(std::uint32_t type)
		{
			switch (type)
			{
			case 1:
				return "object";
			case 2:
				return "executable";
			case 3:
				return "fixed_vm_library";
			case 4:
				return "core";
			case 5:
				return "preload";
			case 6:
				return "dynamic_library";
			case 8:
				return "bundle";
			case 10:
				return "dynamic_linker";
			case 11:
				return "kext_bundle";
			case 12:
				return "fileset";
			default:
				return "unknown";
			}
		}

		struct ElfHeader
		{
			std::uint64_t address = 0;
			bool little = true;
			bool is64 = false;
			std::uint8_t osAbi = 0;
			std::uint8_t abiVersion = 0;
			std::uint16_t type = 0;
			std::uint16_t machine = 0;
			std::uint64_t entry = 0;
			std::uint64_t programOffset = 0;
			std::uint64_t sectionOffset = 0;
			std::uint32_t flags = 0;
			std::uint16_t headerSize = 0;
			std::uint16_t programEntrySize = 0;
			std::uint16_t programCount = 0;
			std::uint16_t sectionEntrySize = 0;
			std::uint16_t sectionCount = 0;
			std::uint16_t sectionNameIndex = 0;
		};

		ElfHeader ParseElfHeader(BinaryNinja::BinaryView* view)
		{
			ElfHeader result;
			result.address = HeaderAddress(view, "__elf_header");
			ViewReader reader(view);
			const auto ident = reader.Bytes(result.address, 16);
			if (ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F')
				throw std::runtime_error("BinaryView does not contain a mapped ELF header");
			if (ident[4] != 1 && ident[4] != 2)
				throw std::runtime_error("ELF header has an unsupported class");
			if (ident[5] != 1 && ident[5] != 2)
				throw std::runtime_error("ELF header has an unsupported byte order");
			result.is64 = ident[4] == 2;
			result.little = ident[5] == 1;
			result.osAbi = ident[7];
			result.abiVersion = ident[8];
			reader.SetLittleEndian(result.little);
			result.type = reader.U16(result.address + 16);
			result.machine = reader.U16(result.address + 18);
			result.entry = result.is64 ? reader.U64(result.address + 24) : reader.U32(result.address + 24);
			result.programOffset = result.is64 ? reader.U64(result.address + 32) : reader.U32(result.address + 28);
			result.sectionOffset = result.is64 ? reader.U64(result.address + 40) : reader.U32(result.address + 32);
			result.flags = reader.U32(result.address + (result.is64 ? 48 : 36));
			result.headerSize = reader.U16(result.address + (result.is64 ? 52 : 40));
			result.programEntrySize = reader.U16(result.address + (result.is64 ? 54 : 42));
			result.programCount = reader.U16(result.address + (result.is64 ? 56 : 44));
			result.sectionEntrySize = reader.U16(result.address + (result.is64 ? 58 : 46));
			result.sectionCount = reader.U16(result.address + (result.is64 ? 60 : 48));
			result.sectionNameIndex = reader.U16(result.address + (result.is64 ? 62 : 50));
			return result;
		}

		struct ElfProgramHeader
		{
			std::size_t index = 0;
			std::uint32_t type = 0;
			std::uint32_t flags = 0;
			std::uint64_t offset = 0;
			std::uint64_t virtualAddress = 0;
			std::uint64_t physicalAddress = 0;
			std::uint64_t fileSize = 0;
			std::uint64_t memorySize = 0;
			std::uint64_t alignment = 0;
		};

		std::string_view ElfProgramType(std::uint32_t type)
		{
			switch (type)
			{
			case 0:
				return "PT_NULL";
			case 1:
				return "PT_LOAD";
			case 2:
				return "PT_DYNAMIC";
			case 3:
				return "PT_INTERP";
			case 4:
				return "PT_NOTE";
			case 5:
				return "PT_SHLIB";
			case 6:
				return "PT_PHDR";
			case 7:
				return "PT_TLS";
			case 0x6474e550:
				return "PT_GNU_EH_FRAME";
			case 0x6474e551:
				return "PT_GNU_STACK";
			case 0x6474e552:
				return "PT_GNU_RELRO";
			default:
				return "UNKNOWN";
			}
		}

		std::vector<ElfProgramHeader> ElfProgramHeaders(BinaryNinja::BinaryView* view, const ElfHeader& header)
		{
			if (header.programCount != 0 && header.programEntrySize < (header.is64 ? 56 : 32))
				throw std::runtime_error("ELF program-header entry size is too small");
			const auto symbol = view->GetSymbolByRawName("__elf_program_headers");
			if (!symbol && header.programCount != 0)
				throw std::runtime_error("ELF program headers are not mapped in this BinaryView");
			const auto base = symbol ? symbol->GetAddress() : 0;
			ViewReader reader(view, header.little);
			std::vector<ElfProgramHeader> result;
			result.reserve(header.programCount);
			for (std::size_t index = 0; index < header.programCount; ++index)
			{
				const auto address = base + index * header.programEntrySize;
				ElfProgramHeader item;
				item.index = index;
				item.type = reader.U32(address);
				if (header.is64)
				{
					item.flags = reader.U32(address + 4);
					item.offset = reader.U64(address + 8);
					item.virtualAddress = reader.U64(address + 16);
					item.physicalAddress = reader.U64(address + 24);
					item.fileSize = reader.U64(address + 32);
					item.memorySize = reader.U64(address + 40);
					item.alignment = reader.U64(address + 48);
				}
				else
				{
					item.offset = reader.U32(address + 4);
					item.virtualAddress = reader.U32(address + 8);
					item.physicalAddress = reader.U32(address + 12);
					item.fileSize = reader.U32(address + 16);
					item.memorySize = reader.U32(address + 20);
					item.flags = reader.U32(address + 24);
					item.alignment = reader.U32(address + 28);
				}
				result.push_back(item);
			}
			return result;
		}

		std::string_view ElfType(std::uint16_t type)
		{
			switch (type)
			{
			case 0:
				return "none";
			case 1:
				return "relocatable";
			case 2:
				return "executable";
			case 3:
				return "shared_object";
			case 4:
				return "core";
			default:
				return "processor_specific";
			}
		}

		std::string_view ElfOsAbi(std::uint8_t value)
		{
			switch (value)
			{
			case 0:
				return "System V";
			case 2:
				return "NetBSD";
			case 3:
				return "Linux";
			case 6:
				return "Solaris";
			case 9:
				return "FreeBSD";
			case 12:
				return "OpenBSD";
			default:
				return "Other";
			}
		}

		struct ElfDynamicEntry
		{
			std::size_t index = 0;
			std::int64_t tag = 0;
			std::uint64_t value = 0;
			std::string text;
		};

		std::string_view ElfDynamicTag(std::int64_t tag, std::uint16_t machine)
		{
			const bool mips = machine == EM_MIPS || machine == EM_MIPS_RS3_LE || machine == EM_MIPS_X;
			if (tag == ELF_DT_MIPS_RLD_VERSION)
			{
				if (machine == EM_SPARC || machine == EM_SPARC32PLUS || machine == EM_SPARCV9)
					return "DT_SPARC_REGISTER";
				return mips ? "DT_MIPS_RLD_VERSION" : "UNKNOWN";
			}
			if (tag >= ELF_DT_MIPS_TIME_STAMP && tag <= ELF_DT_MIPS_RLD_MAP_REL && !mips)
				return "UNKNOWN";
			switch (tag)
			{
			case ELF_DT_NULL:
				return "DT_NULL";
			case ELF_DT_NEEDED:
				return "DT_NEEDED";
			case ELF_DT_PLTRELSZ:
				return "DT_PLTRELSZ";
			case ELF_DT_PLTGOT:
				return "DT_PLTGOT";
			case ELF_DT_HASH:
				return "DT_HASH";
			case ELF_DT_STRTAB:
				return "DT_STRTAB";
			case ELF_DT_SYMTAB:
				return "DT_SYMTAB";
			case ELF_DT_RELA:
				return "DT_RELA";
			case ELF_DT_RELASZ:
				return "DT_RELASZ";
			case ELF_DT_RELAENT:
				return "DT_RELAENT";
			case ELF_DT_STRSZ:
				return "DT_STRSZ";
			case ELF_DT_SYMENT:
				return "DT_SYMENT";
			case ELF_DT_INIT:
				return "DT_INIT";
			case ELF_DT_FINI:
				return "DT_FINI";
			case ELF_DT_SONAME:
				return "DT_SONAME";
			case ELF_DT_RPATH:
				return "DT_RPATH";
			case ELF_DT_SYMBOLIC:
				return "DT_SYMBOLIC";
			case ELF_DT_REL:
				return "DT_REL";
			case ELF_DT_RELSZ:
				return "DT_RELSZ";
			case ELF_DT_RELENT:
				return "DT_RELENT";
			case ELF_DT_PLTREL:
				return "DT_PLTREL";
			case ELF_DT_DEBUG:
				return "DT_DEBUG";
			case ELF_DT_TEXTREL:
				return "DT_TEXTREL";
			case ELF_DT_JMPREL:
				return "DT_JMPREL";
			case ELF_DT_BIND_NOW:
				return "DT_BIND_NOW";
			case ELF_DT_INIT_ARRAY:
				return "DT_INIT_ARRAY";
			case ELF_DT_FINI_ARRAY:
				return "DT_FINI_ARRAY";
			case ELF_DT_INIT_ARRAYSZ:
				return "DT_INIT_ARRAYSZ";
			case ELF_DT_FINI_ARRAYSZ:
				return "DT_FINI_ARRAYSZ";
			case ELF_DT_RUNPATH:
				return "DT_RUNPATH";
			case ELF_DT_FLAGS:
				return "DT_FLAGS";
			case ELF_DT_ENCODING:
				return "DT_ENCODING";
			case ELF_DT_PREINIT_ARRAY:
				return "DT_PREINIT_ARRAY";
			case ELF_DT_PREINIT_ARRAYSZ:
				return "DT_PREINIT_ARRAYSZ";
			case ELF_DT_LOOS:
				return "DT_LOOS";
			case ELF_DT_SUNW_RTLDINF:
				return "DT_SUNW_RTLDINF";
			case ELF_DT_HIOS:
				return "DT_HIOS";
			case ELF_DT_VALRNGLO:
				return "DT_VALRNGLO";
			case ELF_DT_CHECKSUM:
				return "DT_CHECKSUM";
			case ELF_DT_PLTPADSZ:
				return "DT_PLTPADSZ";
			case ELF_DT_MOVEEN:
				return "DT_MOVEENT";
			case ELF_DT_MOVES:
				return "DT_MOVESZ";
			case ELF_DT_FEATURE_1:
				return "DT_FEATURE_1";
			case ELF_DT_POSFLAG_1:
				return "DT_POSFLAG_1";
			case ELF_DT_SYMINSZ:
				return "DT_SYMINSZ";
			case ELF_DT_SYMINENT:
				return "DT_SYMINENT";
			case ELF_DT_ADDRRNGLO:
				return "DT_ADDRRNGLO";
			case ELF_DT_GNU_HASH:
				return "DT_GNU_HASH";
			case ELF_DT_CONFIG:
				return "DT_CONFIG";
			case ELF_DT_DEPAUDIT:
				return "DT_DEPAUDIT";
			case ELF_DT_AUDIT:
				return "DT_AUDIT";
			case ELF_DT_PLTPAD:
				return "DT_PLTPAD";
			case ELF_DT_MOVETAB:
				return "DT_MOVETAB";
			case ELF_DT_SYMINFO:
				return "DT_SYMINFO";
			case ELF_DT_VERSYM:
				return "DT_VERSYM";
			case ELF_DT_RELACOUNT:
				return "DT_RELACOUNT";
			case ELF_DT_RELCOUNT:
				return "DT_RELCOUNT";
			case ELF_DT_FLAGS_1:
				return "DT_FLAGS_1";
			case ELF_DT_VERDEF:
				return "DT_VERDEF";
			case ELF_DT_VERDEFNUM:
				return "DT_VERDEFNUM";
			case ELF_DT_VERNEED:
				return "DT_VERNEED";
			case ELF_DT_VERNEEDNUM:
				return "DT_VERNEEDNUM";
			case ELF_DT_LOPROC:
				return "DT_LOPROC";
			case ELF_DT_MIPS_TIME_STAMP:
				return "DT_MIPS_TIME_STAMP";
			case ELF_DT_MIPS_ICHECKSUM:
				return "DT_MIPS_ICHECKSUM";
			case ELF_DT_MIPS_IVERSION:
				return "DT_MIPS_IVERSION";
			case ELF_DT_MIPS_FLAGS:
				return "DT_MIPS_FLAGS";
			case ELF_DT_MIPS_BASE_ADDRESS:
				return "DT_MIPS_BASE_ADDRESS";
			case ELF_DT_MIPS_CONFLICT:
				return "DT_MIPS_CONFLICT";
			case ELF_DT_MIPS_LIBLIST:
				return "DT_MIPS_LIBLIST";
			case ELF_DT_MIPS_LOCAL_GOTNO:
				return "DT_MIPS_LOCAL_GOTNO";
			case ELF_DT_MIPS_CONFLICTNO:
				return "DT_MIPS_CONFLICTNO";
			case ELF_DT_MIPS_LIBLISTNO:
				return "DT_MIPS_LIBLISTNO";
			case ELF_DT_MIPS_SYMTABNO:
				return "DT_MIPS_SYMTABNO";
			case ELF_DT_MIPS_UNREFEXTNO:
				return "DT_MIPS_UNREFEXTNO";
			case ELF_DT_MIPS_GOTSYM:
				return "DT_MIPS_GOTSYM";
			case ELF_DT_MIPS_HIPAGENO:
				return "DT_MIPS_HIPAGENO";
			case ELF_DT_MIPS_RLD_MAP:
				return "DT_MIPS_RLD_MAP";
			case ELF_DT_MIPS_RLD_MAP_REL:
				return "DT_MIPS_RLD_MAP_REL";
			case ELF_DT_AUXILIARY:
				return "DT_AUXILIARY";
			case ELF_DT_USED:
				return "DT_USED";
			case ELF_DT_FILTER:
				return "DT_FILTER";
			default:
				return "UNKNOWN";
			}
		}

		bool ElfDynamicStringTag(std::int64_t tag)
		{
			return tag == ELF_DT_NEEDED || tag == ELF_DT_SONAME || tag == ELF_DT_RPATH || tag == ELF_DT_RUNPATH
				|| tag == ELF_DT_CONFIG || tag == ELF_DT_DEPAUDIT || tag == ELF_DT_AUDIT || tag == ELF_DT_MIPS_IVERSION
				|| tag == ELF_DT_AUXILIARY || tag == ELF_DT_FILTER;
		}

		std::vector<ElfDynamicEntry> ElfDynamicEntries(BinaryNinja::BinaryView* view, const ElfHeader& header)
		{
			const auto symbol = view->GetSymbolByRawName("__elf_dynamic_table");
			if (!symbol)
				return {};
			const auto dynamicAddress = symbol->GetAddress();
			std::uint64_t maximumBytes = 0;
			for (const auto& section : view->GetSectionsAt(dynamicAddress))
				maximumBytes = std::max(maximumBytes, section->GetEnd() - dynamicAddress);
			if (maximumBytes == 0)
				maximumBytes = (header.is64 ? 16 : 8) * kMaximumHeaderRows;
			const auto entrySize = header.is64 ? 16ULL : 8ULL;
			const auto maximumEntries = std::min<std::uint64_t>(maximumBytes / entrySize, kMaximumHeaderRows);
			const auto strings = view->GetSectionByName(".dynstr");
			ViewReader reader(view, header.little);
			std::vector<ElfDynamicEntry> result;
			for (std::size_t index = 0; index < maximumEntries; ++index)
			{
				const auto address = dynamicAddress + index * entrySize;
				const auto rawTag = header.is64 ? reader.U64(address) : reader.U32(address);
				const auto tag = header.is64 ?
					static_cast<std::int64_t>(rawTag) :
					static_cast<std::int64_t>(static_cast<std::int32_t>(rawTag));
				const auto value = header.is64 ? reader.U64(address + 8) : reader.U32(address + 4);
				ElfDynamicEntry item {index, tag, value, {}};
				if (strings && ElfDynamicStringTag(tag) && value < strings->GetLength())
					item.text = reader.CString(strings->GetStart() + value,
						static_cast<std::size_t>(std::min<std::uint64_t>(strings->GetLength() - value, 4096)));
				result.push_back(std::move(item));
				if (tag == 0)
					break;
			}
			return result;
		}

		struct PeHeader
		{
			std::uint64_t address = 0;
			std::uint64_t peAddress = 0;
			std::uint64_t optionalAddress = 0;
			bool is64 = false;
			std::uint16_t machine = 0;
			std::uint16_t sectionCount = 0;
			std::uint32_t timestamp = 0;
			std::uint16_t optionalSize = 0;
			std::uint16_t characteristics = 0;
			std::uint8_t linkerMajor = 0;
			std::uint8_t linkerMinor = 0;
			std::uint32_t entryRva = 0;
			std::uint64_t imageBase = 0;
			std::uint32_t sectionAlignment = 0;
			std::uint32_t fileAlignment = 0;
			std::uint32_t imageSize = 0;
			std::uint32_t headersSize = 0;
			std::uint32_t checksum = 0;
			std::uint16_t subsystem = 0;
			std::uint16_t dllCharacteristics = 0;
			std::uint32_t directoryCount = 0;
			std::uint64_t directoryAddress = 0;
		};

		PeHeader ParsePeHeader(BinaryNinja::BinaryView* view)
		{
			PeHeader result;
			result.address = HeaderAddress(view, "__dos_header");
			ViewReader reader(view);
			if (reader.U16(result.address) != 0x5a4d)
				throw std::runtime_error("BinaryView does not contain a mapped PE DOS header");
			const auto peOffset = reader.U32(result.address + 0x3c);
			if (peOffset > 256 * 1024 * 1024)
				throw std::runtime_error("PE header offset is unreasonable");
			result.peAddress = result.address + peOffset;
			if (reader.U32(result.peAddress) != 0x00004550)
				throw std::runtime_error("PE signature is missing");
			result.machine = reader.U16(result.peAddress + 4);
			result.sectionCount = reader.U16(result.peAddress + 6);
			result.timestamp = reader.U32(result.peAddress + 8);
			result.optionalSize = reader.U16(result.peAddress + 20);
			result.characteristics = reader.U16(result.peAddress + 22);
			result.optionalAddress = result.peAddress + 24;
			const auto magic = reader.U16(result.optionalAddress);
			if (magic != 0x10b && magic != 0x20b)
				throw std::runtime_error("PE optional header has an unsupported magic value");
			result.is64 = magic == 0x20b;
			const auto minimumSize = result.is64 ? 112U : 96U;
			if (result.optionalSize < minimumSize)
				throw std::runtime_error("PE optional header is truncated");
			result.linkerMajor = reader.U8(result.optionalAddress + 2);
			result.linkerMinor = reader.U8(result.optionalAddress + 3);
			result.entryRva = reader.U32(result.optionalAddress + 16);
			result.imageBase =
				result.is64 ? reader.U64(result.optionalAddress + 24) : reader.U32(result.optionalAddress + 28);
			result.sectionAlignment = reader.U32(result.optionalAddress + 32);
			result.fileAlignment = reader.U32(result.optionalAddress + 36);
			result.imageSize = reader.U32(result.optionalAddress + 56);
			result.headersSize = reader.U32(result.optionalAddress + 60);
			result.checksum = reader.U32(result.optionalAddress + 64);
			result.subsystem = reader.U16(result.optionalAddress + 68);
			result.dllCharacteristics = reader.U16(result.optionalAddress + 70);
			result.directoryCount = reader.U32(result.optionalAddress + (result.is64 ? 108 : 92));
			result.directoryAddress = result.optionalAddress + (result.is64 ? 112 : 96);
			const auto availableDirectories = (result.optionalSize - minimumSize) / 8;
			result.directoryCount = std::min(result.directoryCount, availableDirectories);
			if (result.directoryCount > kMaximumHeaderRows)
				throw std::runtime_error("PE data-directory count is unreasonable");
			return result;
		}

		std::string_view PeMachine(std::uint16_t machine)
		{
			switch (machine)
			{
			case 0x14c:
				return "i386";
			case 0x1c0:
				return "arm";
			case 0x1c4:
				return "armv7";
			case 0x8664:
				return "x86_64";
			case 0xaa64:
				return "arm64";
			default:
				return "unknown";
			}
		}

		std::string_view PeSubsystem(std::uint16_t subsystem)
		{
			switch (subsystem)
			{
			case 1:
				return "native";
			case 2:
				return "windows_gui";
			case 3:
				return "windows_console";
			case 7:
				return "posix_console";
			case 9:
				return "windows_ce_gui";
			case 10:
				return "efi_application";
			case 11:
				return "efi_boot_service_driver";
			case 12:
				return "efi_runtime_driver";
			case 14:
				return "xbox";
			default:
				return "unknown";
			}
		}

		struct PeDirectory
		{
			std::size_t index = 0;
			std::string_view name;
			std::uint32_t rva = 0;
			std::uint32_t size = 0;
		};

		std::vector<PeDirectory> PeDirectories(BinaryNinja::BinaryView* view, const PeHeader& header)
		{
			static constexpr std::array names {"export", "import", "resource", "exception", "certificate",
				"base_relocation", "debug", "architecture", "global_pointer", "tls", "load_config", "bound_import",
				"iat", "delay_import", "clr_runtime", "reserved"};
			ViewReader reader(view);
			std::vector<PeDirectory> result;
			result.reserve(header.directoryCount);
			for (std::size_t index = 0; index < header.directoryCount; ++index)
			{
				const auto address = header.directoryAddress + index * 8;
				result.push_back({index, index < names.size() ? names[index] : "unknown", reader.U32(address),
					reader.U32(address + 4)});
			}
			return result;
		}

		struct LinkedLibrary
		{
			std::string name;
			std::string kind;
		};

		std::vector<LinkedLibrary> LinkedLibraries(BinaryNinja::BinaryView* view)
		{
			std::vector<LinkedLibrary> result;
			const auto viewType = view->GetTypeName();
			if (viewType == "Mach-O")
			{
				const auto header = ParseMachHeader(view);
				for (const auto& command : MachCommands(view, header))
				{
					if (!IsMachDylibCommand(command.command) || command.command == 0xd)
						continue;
					result.push_back(
						{MachCommandString(view, header, command), std::string(MachCommandName(command.command))});
				}
			}
			else if (viewType == "ELF")
			{
				const auto header = ParseElfHeader(view);
				for (const auto& entry : ElfDynamicEntries(view, header))
					if (entry.tag == 1 && !entry.text.empty())
						result.push_back({entry.text, "needed"});
			}
			else if (viewType == "PE")
			{
				const auto header = ParsePeHeader(view);
				const auto directories = PeDirectories(view, header);
				ViewReader reader(view);
				const auto parseDirectory = [&](std::size_t index, bool delay) {
					if (index >= directories.size() || directories[index].rva == 0)
						return;
					const auto& directory = directories[index];
					const auto entrySize = delay ? 32U : 20U;
					const auto maximum = std::min<std::size_t>(
						directory.size == 0 ? kMaximumHeaderRows : directory.size / entrySize + 1, kMaximumHeaderRows);
					for (std::size_t entry = 0; entry < maximum; ++entry)
					{
						const auto address = view->GetImageBase() + directory.rva + entry * entrySize;
						const auto attributes = delay ? reader.U32(address) : 1U;
						const auto nameValue = reader.U32(address + (delay ? 4 : 12));
						if (nameValue == 0)
							break;
						const auto nameAddress =
							delay && (attributes & 1) == 0 ? nameValue : view->GetImageBase() + nameValue;
						result.push_back({reader.CString(nameAddress), delay ? "delay_import" : "import"});
					}
				};
				parseDirectory(1, false);
				parseDirectory(13, true);
			}
			else
				throw std::runtime_error("Header Parsing supports materialized Mach-O, ELF, and PE BinaryViews");

			std::set<std::string> present;
			for (const auto& library : result)
				present.insert(library.name);
			for (const auto& library : view->GetExternalLibraries())
				if (library && !present.contains(library->GetName()))
					result.push_back({library->GetName(), "external"});
			std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
				return left.name < right.name || (left.name == right.name && left.kind < right.kind);
			});
			return result;
		}

		template <typename Item, typename Search, typename Write>
		ipc::Reply WritePaginated(
			std::string_view key, std::vector<Item> items, const ListArguments& arguments, Search search, Write write)
		{
			if (!arguments.query.empty())
				std::erase_if(items, [&](const auto& item) {
					return Lower(search(item)).find(arguments.query) == std::string::npos;
				});
			const auto offset = std::min(arguments.offset, items.size());
			const auto finish = offset + std::min(arguments.limit, items.size() - offset);
			return JsonReply([&](auto& writer) {
				writer.Key(key.data(), static_cast<rapidjson::SizeType>(key.size()));
				writer.StartArray();
				for (std::size_t index = offset; index < finish; ++index)
					write(writer, items[index]);
				writer.EndArray();
				writer.Key("count");
				writer.Uint64(finish - offset);
				writer.Key("total");
				writer.Uint64(items.size());
				writer.Key("nextOffset");
				if (finish < items.size())
					writer.Uint64(finish);
				else
					writer.Null();
				writer.Key("truncated");
				writer.Bool(finish < items.size());
			});
		}

		ipc::Reply BinaryHeaderInfo(const FileChildToolCallContext& command)
		{
			const auto view = command.view->view;
			const auto viewType = view->GetTypeName();
			if (viewType != "Mach-O" && viewType != "ELF" && viewType != "PE")
				throw std::runtime_error("Header Parsing supports materialized Mach-O, ELF, and PE BinaryViews");
			return JsonReply([&](auto& writer) {
				WriteText(writer, "format", viewType);
				if (const auto architecture = view->GetDefaultArchitecture())
					WriteText(writer, "architecture", architecture->GetName());
				if (const auto platform = view->GetDefaultPlatform())
					WriteText(writer, "platform", platform->GetName());
				WriteText(writer, "endianness", view->GetDefaultEndianness() == LittleEndian ? "little" : "big");
				writer.Key("addressSize");
				writer.Uint64(view->GetAddressSize());
				WriteText(writer, "imageBase", HexAddress(view->GetImageBase()));
				WriteText(writer, "originalImageBase", HexAddress(view->GetOriginalImageBase()));
				WriteText(writer, "entryPoint", HexAddress(view->GetEntryPoint()));
				writer.Key("executable");
				writer.Bool(view->IsExecutable());
				writer.Key("relocatable");
				writer.Bool(view->IsRelocatable());
				writer.Key("header");
				writer.StartObject();
				if (viewType == "Mach-O")
				{
					const auto header = ParseMachHeader(view);
					writer.Key("bits");
					writer.Uint(header.is64 ? 64 : 32);
					writer.Key("cpuType");
					writer.Uint(header.cpuType);
					writer.Key("cpuSubtype");
					writer.Uint(header.cpuSubtype);
					WriteText(writer, "fileType", MachFileType(header.fileType));
					writer.Key("fileTypeValue");
					writer.Uint(header.fileType);
					writer.Key("flags");
					writer.Uint(header.flags);
					writer.Key("loadCommandCount");
					writer.Uint(header.commandCount);
					writer.Key("loadCommandBytes");
					writer.Uint(header.commandBytes);
					std::string uuid;
					std::string installName;
					std::vector<std::string> rpaths;
					std::optional<std::uint32_t> buildPlatform;
					std::string minimumOs;
					std::string sdk;
					bool codeSigned = false;
					bool encrypted = false;
					for (const auto& item : MachCommands(view, header))
					{
						ViewReader reader(view, header.little);
						if (item.command == 0x1b && item.size >= 24)
							uuid = Uuid(reader.Bytes(item.address + 8, 16));
						else if (item.command == 0xd)
							installName = MachCommandString(view, header, item);
						else if (item.command == 0x8000001c)
							rpaths.push_back(MachCommandString(view, header, item));
						else if (item.command == 0x32 && item.size >= 24)
						{
							buildPlatform = reader.U32(item.address + 8);
							minimumOs = PackedVersion(reader.U32(item.address + 12));
							sdk = PackedVersion(reader.U32(item.address + 16));
						}
						else if ((item.command == 0x24 || item.command == 0x25 || item.command == 0x2f
									 || item.command == 0x30)
							&& item.size >= 16)
						{
							minimumOs = PackedVersion(reader.U32(item.address + 8));
							sdk = PackedVersion(reader.U32(item.address + 12));
						}
						else if (item.command == 0x1d)
							codeSigned = true;
						else if ((item.command == 0x21 || item.command == 0x2c) && item.size >= 20)
							encrypted = reader.U32(item.address + 16) != 0;
					}
					if (!uuid.empty())
						WriteText(writer, "uuid", uuid);
					if (!installName.empty())
						WriteText(writer, "installName", installName);
					writer.Key("rpaths");
					writer.StartArray();
					for (const auto& path : rpaths)
						writer.String(path.data(), static_cast<rapidjson::SizeType>(path.size()));
					writer.EndArray();
					if (buildPlatform)
					{
						writer.Key("buildPlatform");
						writer.Uint(*buildPlatform);
					}
					if (!minimumOs.empty())
						WriteText(writer, "minimumOs", minimumOs);
					if (!sdk.empty())
						WriteText(writer, "sdk", sdk);
					writer.Key("codeSigned");
					writer.Bool(codeSigned);
					writer.Key("encrypted");
					writer.Bool(encrypted);
					writer.Key("pie");
					writer.Bool((header.flags & 0x200000) != 0);
					writer.Key("noHeapExecution");
					writer.Bool((header.flags & 0x1000000) != 0);
				}
				else if (viewType == "ELF")
				{
					const auto header = ParseElfHeader(view);
					writer.Key("bits");
					writer.Uint(header.is64 ? 64 : 32);
					WriteText(writer, "osAbi", ElfOsAbi(header.osAbi));
					writer.Key("osAbiValue");
					writer.Uint(header.osAbi);
					writer.Key("abiVersion");
					writer.Uint(header.abiVersion);
					WriteText(writer, "objectType", ElfType(header.type));
					writer.Key("objectTypeValue");
					writer.Uint(header.type);
					writer.Key("machine");
					writer.Uint(header.machine);
					writer.Key("flags");
					writer.Uint(header.flags);
					writer.Key("headerSize");
					writer.Uint(header.headerSize);
					writer.Key("programHeaderCount");
					writer.Uint(header.programCount);
					writer.Key("sectionHeaderCount");
					writer.Uint(header.sectionCount);
					if (const auto interpreter = view->GetSymbolByRawName("__elf_interp"))
						WriteText(
							writer, "interpreter", ViewReader(view, header.little).CString(interpreter->GetAddress()));
					bool executableStack = false;
					bool relro = false;
					for (const auto& item : ElfProgramHeaders(view, header))
					{
						if (item.type == 0x6474e551)
							executableStack = (item.flags & 1) != 0;
						if (item.type == 0x6474e552)
							relro = true;
					}
					writer.Key("executableStack");
					writer.Bool(executableStack);
					writer.Key("gnuRelro");
					writer.Bool(relro);
					for (const auto& item : ElfDynamicEntries(view, header))
					{
						if (item.tag == 14 && !item.text.empty())
							WriteText(writer, "soname", item.text);
						if (item.tag == 15 && !item.text.empty())
							WriteText(writer, "rpath", item.text);
						if (item.tag == 29 && !item.text.empty())
							WriteText(writer, "runpath", item.text);
					}
				}
				else
				{
					const auto header = ParsePeHeader(view);
					writer.Key("bits");
					writer.Uint(header.is64 ? 64 : 32);
					WriteText(writer, "machine", PeMachine(header.machine));
					writer.Key("machineValue");
					writer.Uint(header.machine);
					writer.Key("sectionCount");
					writer.Uint(header.sectionCount);
					writer.Key("timestamp");
					writer.Uint(header.timestamp);
					writer.Key("characteristics");
					writer.Uint(header.characteristics);
					WriteText(writer, "linkerVersion",
						std::to_string(header.linkerMajor) + '.' + std::to_string(header.linkerMinor));
					WriteText(writer, "preferredImageBase", HexAddress(header.imageBase));
					WriteText(writer, "entryRva", HexAddress(header.entryRva));
					WriteText(writer, "subsystem", PeSubsystem(header.subsystem));
					writer.Key("subsystemValue");
					writer.Uint(header.subsystem);
					writer.Key("dllCharacteristics");
					writer.Uint(header.dllCharacteristics);
					writer.Key("imageSize");
					writer.Uint(header.imageSize);
					writer.Key("headersSize");
					writer.Uint(header.headersSize);
					writer.Key("sectionAlignment");
					writer.Uint(header.sectionAlignment);
					writer.Key("fileAlignment");
					writer.Uint(header.fileAlignment);
					writer.Key("checksum");
					writer.Uint(header.checksum);
					writer.Key("dataDirectoryCount");
					writer.Uint(header.directoryCount);
					writer.Key("dynamicBase");
					writer.Bool((header.dllCharacteristics & 0x40) != 0);
					writer.Key("nxCompatible");
					writer.Bool((header.dllCharacteristics & 0x100) != 0);
					writer.Key("controlFlowGuard");
					writer.Bool((header.dllCharacteristics & 0x4000) != 0);
				}
				writer.EndObject();
			});
		}

		ipc::Reply LinkedLibraryList(const FileChildToolCallContext& command)
		{
			const auto arguments = ParseListArguments(command.arguments);
			return WritePaginated(
				"libraries", LinkedLibraries(command.view->view), arguments,
				[](const auto& item) { return item.name + ' ' + item.kind; },
				[](auto& writer, const auto& item) {
					writer.StartObject();
					WriteText(writer, "name", item.name);
					WriteText(writer, "kind", item.kind);
					writer.EndObject();
				});
		}

		ipc::Reply MachoLoadCommandList(const FileChildToolCallContext& command)
		{
			const auto view = command.view->view;
			if (view->GetTypeName() != "Mach-O")
				throw std::runtime_error("bn_macho_load_command_list requires a Mach-O BinaryView");
			const auto header = ParseMachHeader(view);
			const auto arguments = ParseListArguments(command.arguments);
			return WritePaginated(
				"loadCommands", MachCommands(view, header), arguments,
				[](const auto& item) { return std::string(MachCommandName(item.command)); },
				[&](auto& writer, const auto& item) {
					ViewReader reader(view, header.little);
					writer.StartObject();
					writer.Key("index");
					writer.Uint64(item.index);
					WriteText(writer, "address", HexAddress(item.address));
					WriteText(writer, "command", MachCommandName(item.command));
					writer.Key("commandValue");
					writer.Uint(item.command);
					writer.Key("size");
					writer.Uint(item.size);
					writer.Key("required");
					writer.Bool((item.command & 0x80000000U) != 0);
					if (IsMachDylibCommand(item.command))
					{
						WriteText(writer, "name", MachCommandString(view, header, item));
						if (item.size >= 24)
						{
							writer.Key("timestamp");
							writer.Uint(reader.U32(item.address + 12));
							WriteText(writer, "currentVersion", PackedVersion(reader.U32(item.address + 16)));
							WriteText(writer, "compatibilityVersion", PackedVersion(reader.U32(item.address + 20)));
						}
					}
					else if (item.command == 0xe || item.command == 0xf || item.command == 0x8000001c)
						WriteText(writer, "path", MachCommandString(view, header, item));
					else if (item.command == 0x1b && item.size >= 24)
						WriteText(writer, "uuid", Uuid(reader.Bytes(item.address + 8, 16)));
					else if (item.command == 0x80000028 && item.size >= 24)
					{
						writer.Key("entryOffset");
						writer.Uint64(reader.U64(item.address + 8));
						writer.Key("stackSize");
						writer.Uint64(reader.U64(item.address + 16));
					}
					else if (item.command == 0x32 && item.size >= 24)
					{
						writer.Key("platform");
						writer.Uint(reader.U32(item.address + 8));
						WriteText(writer, "minimumOs", PackedVersion(reader.U32(item.address + 12)));
						WriteText(writer, "sdk", PackedVersion(reader.U32(item.address + 16)));
						writer.Key("toolCount");
						writer.Uint(reader.U32(item.address + 20));
					}
					else if ((item.command == 0x24 || item.command == 0x25 || item.command == 0x2f
								 || item.command == 0x30)
						&& item.size >= 16)
					{
						WriteText(writer, "minimumOs", PackedVersion(reader.U32(item.address + 8)));
						WriteText(writer, "sdk", PackedVersion(reader.U32(item.address + 12)));
					}
					else if ((item.command == 0x21 || item.command == 0x2c) && item.size >= 20)
					{
						writer.Key("cryptOffset");
						writer.Uint(reader.U32(item.address + 8));
						writer.Key("cryptSize");
						writer.Uint(reader.U32(item.address + 12));
						writer.Key("cryptId");
						writer.Uint(reader.U32(item.address + 16));
					}
					else if ((item.command == 0x1 || item.command == 0x19)
						&& item.size >= (item.command == 0x19 ? 72U : 56U))
					{
						WriteText(writer, "segment", reader.FixedString(item.address + 8, 16));
						if (item.command == 0x19)
						{
							WriteText(writer, "virtualAddress", HexAddress(reader.U64(item.address + 24)));
							writer.Key("virtualSize");
							writer.Uint64(reader.U64(item.address + 32));
							writer.Key("fileOffset");
							writer.Uint64(reader.U64(item.address + 40));
							writer.Key("fileSize");
							writer.Uint64(reader.U64(item.address + 48));
							writer.Key("sectionCount");
							writer.Uint(reader.U32(item.address + 64));
						}
						else
						{
							WriteText(writer, "virtualAddress", HexAddress(reader.U32(item.address + 24)));
							writer.Key("virtualSize");
							writer.Uint(reader.U32(item.address + 28));
							writer.Key("fileOffset");
							writer.Uint(reader.U32(item.address + 32));
							writer.Key("fileSize");
							writer.Uint(reader.U32(item.address + 36));
							writer.Key("sectionCount");
							writer.Uint(reader.U32(item.address + 48));
						}
					}
					writer.EndObject();
				});
		}

		ipc::Reply ElfProgramHeaderList(const FileChildToolCallContext& command)
		{
			const auto view = command.view->view;
			if (view->GetTypeName() != "ELF")
				throw std::runtime_error("bn_elf_program_header_list requires an ELF BinaryView");
			const auto header = ParseElfHeader(view);
			return WritePaginated(
				"programHeaders", ElfProgramHeaders(view, header), ParseListArguments(command.arguments),
				[](const auto& item) { return std::string(ElfProgramType(item.type)); },
				[](auto& writer, const auto& item) {
					writer.StartObject();
					writer.Key("index");
					writer.Uint64(item.index);
					WriteText(writer, "type", ElfProgramType(item.type));
					writer.Key("typeValue");
					writer.Uint(item.type);
					writer.Key("flags");
					writer.Uint(item.flags);
					writer.Key("readable");
					writer.Bool((item.flags & 4) != 0);
					writer.Key("writable");
					writer.Bool((item.flags & 2) != 0);
					writer.Key("executable");
					writer.Bool((item.flags & 1) != 0);
					writer.Key("fileOffset");
					writer.Uint64(item.offset);
					WriteText(writer, "virtualAddress", HexAddress(item.virtualAddress));
					WriteText(writer, "physicalAddress", HexAddress(item.physicalAddress));
					writer.Key("fileSize");
					writer.Uint64(item.fileSize);
					writer.Key("memorySize");
					writer.Uint64(item.memorySize);
					writer.Key("alignment");
					writer.Uint64(item.alignment);
					writer.EndObject();
				});
		}

		ipc::Reply ElfDynamicEntryList(const FileChildToolCallContext& command)
		{
			const auto view = command.view->view;
			if (view->GetTypeName() != "ELF")
				throw std::runtime_error("bn_elf_dynamic_entry_list requires an ELF BinaryView");
			const auto header = ParseElfHeader(view);
			return WritePaginated(
				"dynamicEntries", ElfDynamicEntries(view, header), ParseListArguments(command.arguments),
				[&header](const auto& item) {
					return std::string(ElfDynamicTag(item.tag, header.machine)) + ' ' + item.text;
				},
				[&header](auto& writer, const auto& item) {
					writer.StartObject();
					writer.Key("index");
					writer.Uint64(item.index);
					WriteText(writer, "tag", ElfDynamicTag(item.tag, header.machine));
					writer.Key("tagValue");
					writer.Int64(item.tag);
					writer.Key("value");
					writer.Uint64(item.value);
					if (!item.text.empty())
						WriteText(writer, "string", item.text);
					writer.EndObject();
				});
		}

		ipc::Reply PeDataDirectoryList(const FileChildToolCallContext& command)
		{
			const auto view = command.view->view;
			if (view->GetTypeName() != "PE")
				throw std::runtime_error("bn_pe_data_directory_list requires a PE BinaryView");
			const auto header = ParsePeHeader(view);
			return WritePaginated(
				"dataDirectories", PeDirectories(view, header), ParseListArguments(command.arguments),
				[](const auto& item) { return std::string(item.name); },
				[&](auto& writer, const auto& item) {
					writer.StartObject();
					writer.Key("index");
					writer.Uint64(item.index);
					WriteText(writer, "name", item.name);
					if (item.index == 4)
						WriteText(writer, "fileOffset", HexAddress(item.rva));
					else
					{
						WriteText(writer, "rva", HexAddress(item.rva));
						if (item.rva != 0)
							WriteText(writer, "address", HexAddress(view->GetImageBase() + item.rva));
					}
					writer.Key("size");
					writer.Uint(item.size);
					writer.EndObject();
				});
		}

#define BINJAD_HEADER_TOOL(Type, Name, Handler) \
	class Type final : public FileChildToolCall \
	{ \
	public: \
		Type() : FileChildToolCall(Name) {} \
		ipc::Reply Execute(const FileChildToolCallContext& context) const override { return Handler(context); } \
	}

		BINJAD_HEADER_TOOL(BinaryHeaderInfoTool, "bn_binary_header_info", BinaryHeaderInfo);
		BINJAD_HEADER_TOOL(LinkedLibraryListTool, "bn_linked_library_list", LinkedLibraryList);
		BINJAD_HEADER_TOOL(MachoLoadCommandListTool, "bn_macho_load_command_list", MachoLoadCommandList);
		BINJAD_HEADER_TOOL(ElfProgramHeaderListTool, "bn_elf_program_header_list", ElfProgramHeaderList);
		BINJAD_HEADER_TOOL(ElfDynamicEntryListTool, "bn_elf_dynamic_entry_list", ElfDynamicEntryList);
		BINJAD_HEADER_TOOL(PeDataDirectoryListTool, "bn_pe_data_directory_list", PeDataDirectoryList);

#undef BINJAD_HEADER_TOOL
	}  // namespace

	void RegisterHeaderParsingToolCalls(std::vector<std::unique_ptr<FileChildToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<BinaryHeaderInfoTool>());
		tools.emplace_back(std::make_unique<LinkedLibraryListTool>());
		tools.emplace_back(std::make_unique<MachoLoadCommandListTool>());
		tools.emplace_back(std::make_unique<ElfProgramHeaderListTool>());
		tools.emplace_back(std::make_unique<ElfDynamicEntryListTool>());
		tools.emplace_back(std::make_unique<PeDataDirectoryListTool>());
	}
}  // namespace binjad
