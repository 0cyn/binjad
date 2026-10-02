#include "binjad/Config.hpp"

namespace binjad {
	std::string_view DefaultConfigJson()
	{
		return R"json({
  "_comment": "Unknown fields such as _comment are ignored. Known fields are validated strictly.",
  "binary_ninja": {
    "_comment": "Set an absolute Binary Ninja installation root. Leave it empty for the platform default.",
    "installation_dir": ""
  },
  "listener": {
    "addresses": [
      "127.0.0.1",
      "::1"
    ],
    "port": 8712
  },
  "http": {
    "_comment": "Leave public_base_url empty to derive it from the first loopback listener.",
    "public_base_url": "",
    "mcp_path": "/mcp",
    "upload_path": "/uploads",
    "portal_path": "/portal",
    "health_path": "/healthz",
    "mcp_max_body_bytes": 8388608
  },
  "cpu": {
    "percentage": 75,
    "fairness": "job",
    "subdivision": "serial"
  },
  "sessions": {
    "ttl_seconds": 1800
  },
  "jobs": {
    "detach_after_seconds": 30,
    "cancellation_grace_seconds": 5
  },
  "uploads": {
    "max_bytes": 4294967296,
    "memory_threshold_bytes": 268435456,
    "url_ttl_seconds": 3600
  },
  "projects": {
    "_comment": "Relative roots are resolved against this file's directory. Outside-root project creation and registration are disabled unless allow_project_registration is true.",
    "roots": [],
    "default_root": "",
    "allow_arbitrary_paths": true,
    "allow_project_registration": false
  },
  "storage": {
    "_comment": "Empty paths default beside this file.",
    "tokens_path": "",
    "accounts_path": "",
    "spool_path": ""
  },
  "tools": {
    "_comment": "Tool packs are persisted and applied immediately. Discovery mode requires a service restart. Brokered discovery advertises 15 lifecycle/control tools to modern clients and 13 to legacy clients, and routes every other enabled tool through bn_tools.",
    "discovery_mode": "full",
    "project_management": true,
    "function_analysis": true,
    "binary_data": true,
    "search": true,
    "types": true,
    "annotations": true,
    "binary_editing": true,
    "history": true,
    "header_parsing": true,
    "url_generation": true,
    "diffing": true,
    "kernel_cache": true,
    "shared_cache": true,
    "debugger": true
  }
}
)json";
	}
}  // namespace binjad
