# web panel

## visual

* [COMPLETED] Remove text at top that says "MCP / local daemon / v0.1.0 from every page
### MCP / Enabled Tools

* [COMPLETED] Remove "Enabled tool packs" header including subtext
* [COMPLETED] add a very tiny bit of subtext, gray, sitting above the box, that says "Updates immediately on change"

### MCP context view

* [COMPLETED] remove the 5 useless boxes (Protocol date, role, mode, tools, enabled packs)
* [COMPLETED] remove "Exact MCP wire context" box
* [COMPLETED] "opencode-oriented projection" -> "model view"
* [COMPLETED] subtext "This is what a model sees as formatted by opencode"
* [COMPLETED] Add unoutlined gray texts on the top right of the box with a kb size and token estimate, divided by a |
* [COMPLETED] Remove refresh button

### MCP Tool Calls view

* [COMPLETED] Remove refresh button
* [COMPLETED] Remove the 5 boxes
* [COMPLETED] subtext "these are the docs provided to model per toolcall"
* [COMPLETED] Remove subtext on every toolcall

### Access Control

* [COMPLETED] Remove "Reload"
* [COMPLETED] Rename to "Account/Token"
* [COMPLETED] "Revoke token" is not properly padded on the bottom
* [COMPLETED] New Password and Create/Rotate token input boxes dont respond to window resize properly and go outside of their parents

### Configuration

* [COMPLETED] Rename to "Configuration" where it says "Daemon configuration"
* [COMPLETED] Remove the useless subheader text
* [COMPLETED] "Reload" -> "Reload from disk"
* [COMPLETED] "Validate & save" -> "Save"
* [COMPLETED] "Allow admin arbitrary-path opens" -> "Tokens can request binaryninja open a local file directly from the MCP computer's disk without requiring uploads"
* [COMPLETED] "Require bearer header on upload requests" -> "Require Bearer Header w/ MCP token on file uploads"
* [COMPLETED] All config options need tooltips. Please use my style of speaking and explaining things when writing them.

### Services: Projects

* [COMPLETED] Needs to be a dropdown in the Services section like the rest of the panel
* [COMPLETED] Create Project button
* [COMPLETED] subtext needs to be changed to "Projects are stored in configured roots, see System/Configuration"

## functionality

* [COMPLETED] The panel needs to be more tightly integrated with the server. Panel should
  poll server for updated state and refresh its views accordingly. Config is an exception where we
  copy-on-read it to local so the user doesn't lose changes there.

* [COMPLETED] Changes to toolcalls need to be hot-applied.
