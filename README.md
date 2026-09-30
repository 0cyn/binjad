![logo](.github/img/logo.png)

<p align="center">
  <a href="#install">install</a> | <a href="#restart-stop">restart</a>
</p>

This is an **UNOFFICIAL** HTTP MCP daemon for BinaryNinja **Commercial Edition** that offers "a few" things the official doesn't, and fixes some of my gripes
trying to work with the official one. It's designed for fully autonomous parallel work with multiple agents at scale, not 
single agent guided analysis.

This runs indefinitely in the background without binaryninja open. Config is done via a web panel, 
and the daemon can be controlled from its macOS menu bar item or through `brew services`. You will need a 
Commercial binaryninja license since that's required for using BinaryNinja headlessly. 

I am not currently an employee or affiliate of Vector 35 and this project is not associated with them in any way.

### big features

* Project support
* Concurrent analysis (there is not an "active view" paradigm)
* KernelCache, SharedCache, Debugger support
* Diffing
* Mach-O, ELF, and PE header/dependency parsing
* binaryninja:// url helper
* Feature parity w/ official MCP; all of the toolcalls from the official are present too
* Files are loaded in individual processes, so crashes do not destroy other unsaved work.
* Project support can be forced, so local LLM agents can work fully sandboxed. 
* Categories of tools can be disabled to save context. 
* Optional "reduced mode" that reduces the list of force-advertised toolcalls to 13-15, if you need that. Still allows querying tools and using all of them. 

"Why not just ask frontier models to write scripts for me" This is tuned to be useful for both frontier models and 
local/prosumer ones. For stuff like Qwen, it lets it work sandboxed w/o needing to give it API scripting or expecting it to nail scripts. 

Additionally, part of the reason I built this was because I've had a 112-core local box i've been dying
to use for analysis runs while doing the actual work on my main laptop. It's a cool way to outsource the analysis
while not working over VNC.


### some other stuff

![img.png](.github/img/menubar.png)

* Markdown and JSON project file readers. Agents loooove putting these in Projects, so I just made it first-class behavior.
* A nice non-claudeslop panel you can use to fuck w/ settings, handle auth, etc.
* it's been tuned to work with smellier local models; several Qwen 3.8 27b agents on a 5090 doing binary analysis in parallel was a common use case while testing
* and on that note, a lot has been done to make sure it doesn't obliterate context
* Web configuration API :thumbsup:


### a demonstration

If you actually pay for compute usage, I'd highly recommend you work out a system with your harness to
outsource interacting with the MCP to lower cost models. Even w/ local models, toolcall corpus gets cached,
its solid.   

The following is an example task (patch-diffing KDKs to look at n-days) for this project. This should collaterally showcase a lot of 
what the MCP can do. It primarily leans on cheap luna agents and burns approx 5% of codex weekly for a task that
involves patchdiffing 800 large kernel extensions for bugs.

Through the power of a codified toolkit, instead of 30 messages and insane token burn trying to steer it to use the API properly,
we can hands-off this task w/o even needing to give the agent filesystem access. Chain this with blacktop's `ipsw` for sourcing the files, 
and tell it to extract and upload the KDKs to the proj beforehand for a truly depressing amount of automation. 

> Take a look at the two KDK revisions in the binjad KDK project. I want you to diff each file and figure out which 
> ones have changes. Once that's done, I want you to use a large amount of luna subagents to dig through the files with
> code changes and identify vulnerability, bug, etc fixes. For each file, do thorough analysis to identify the problem,
> effects, and how it was patched. Generate a markdown report that contains decompiled code representations, nested
> categorization, contains BNURL links to relevant snippets in code and sources for decompiled bits. Keep view handles
> open to avoid reanalysis and don't touch the filesystem for this.

Neat: Due to a binaryninja demangler bug, some stuff in this will crash binaryninja. It won't take out the daemon, and the model will recover
just fine! 

![img.png](.github/img/demo1.png)
<p align="center"><sub>prompt + initial exploration</sub></p>

![img.png](.github/img/demo2.png)
<p align="center"><sub>a subagent digging through the diff</sub></p>

![img.png](.github/img/demoresult.png)
<p align="center"><sub>Digging through the generated report using `bntextviews` (unchecked, probably pretty close, but you've got hotlinks to make that validation so much easier on your end.)</sub></p>


Use this with the `bntextviews` plugin to allow your agents to write markdown/json content into projects you can then display in
BinaryNinja with a nice document reader. It's good!

I've found Qwen 3.8 27b on a 4-bit quant to be very capable of everything this toolkit exposes. Docs have been tuned to 
help lower-spec models through trickier things. 

> fun challenge: figure out how many of these vulnerabilities are actually exploitable ^..^

![img.png](.github/img/panel.png)

<p align="center"><sub>actually, websites can look different from other websites, through the power of trying even a little bit</sub></p>

> Caveat of project work: Due to a binaryninja limitation, if you are running the server locally, having a project in GUI open in any way holds
> a 'lock' on the project, which will result in certain toolcalls that modify projects failing.


### install note

installation is currently done through homebrew. 

The default Binary Ninja locations are `/Applications/Binary Ninja.app` on macOS and `~/binaryninja` on Linux.

For another location, set `binary_ninja.installation_dir` to an absolute path in the configuration and restart the service.

Once installed, start the service, head to http://127.0.0.1:8712/portal, and create the account.

On macOS, You'll be prompted by macOS for keychain password on daemon startup and acct creation since we store keys, login info, and such there. There is also a
menu bar item that allows you to stop/start/restart the daemon, hot-toggle toolkits, view runtime status, and hop back to the portal.

Use the web portal for configuration. The default configuration paths are:

* macOS: `~/Library/Application Support/binjad/config.json`
* Linux: `$XDG_DATA_HOME/binjad/config.json`, or `~/.local/share/binjad/config.json` when `XDG_DATA_HOME` is unset

The installed `binjad` command is a small native launcher with no Binary Ninja dependency.

It reads the configuration, sets the platform library search path, and executes `libexec/binjad-runtime`.

Please thumbs-up the [Windows Support]() or [Linux Support]() issues if you need it on these platforms. 

### install

binja'd (and new versions of it) are released in lockstep with BinaryNinja versions. 

e.g. I push bugfixes, next time binaryninja-api gets pushed by v35 for a dev build it triggers a build on this repo and that bugfix gets rolled
out for the latest version.

I highly reccomend for the time being you run this on a BinaryNinja "Stable" release, to avoid having to update constantly.

##### If you run into a binaryninja bug while using this, file an issue here and we can figure out whether it's a bug w/ this project or with Binary Ninja itself before spamming their repo.


```shell
# The alias selects the current supported Binary Ninja version.
brew install 0cyn/tap/binjad
brew services start 0cyn/tap/binjad

# Open the configuration panel to create the account and MCP token.
open http://127.0.0.1:8712/portal  # macOS
```

Use an explicit formula when you must select a Binary Ninja version:

```shell
brew install 0cyn/tap/binjad@6.1.10695
brew services start 0cyn/tap/binjad@6.1.10695
```

#### restart/stop

```shell
# restart the daemon
brew services restart 0cyn/tap/binjad
# stop it
brew services stop 0cyn/tap/binjad
# start it again
brew services start 0cyn/tap/binjad
```

#### connecting to the MCP

``` json
# example for opencode: 

"binjad": {
  "type": "remote",
  "url": "http://127.0.0.1:8712/mcp",
  "headers": {
    "Authorization": "Bearer TOKEN-COPIED-FROM-WEB-PANEL"
  },
  "enabled": true
}
```

#### exposing on LAN

See [security notes](#security). This daemon will only ever advertise on loopback, you'll need to expose it yourself with
nginx or something.

### commercial license

BinaryNinja Commercial licenses are allowed one active MCP token and one account.

Usage by multiple individuals and/or usage in containerized deployments of infra is disallowed by Binary Ninja's license terms (afaik).

You are intended to use this project on local hardware, by yourself. If you're trying to use this project for anything
other than that, you should probably reach out to their support and ensure you're working within your current license, or 
adjust your license agreement with them accordingly. 

---

### design schtuff

###### those random 4 words smashed together

We use FourWordsLikeThis in place of UUIDs since they should be easier for a very cheap model to remember as compared to a UUID. 

They're used in place of Project UUIDs and BinaryView file IDs. You may see them in UI in a few spots, or 
may see models pass them around. This is how frontier ones can run and monitor analysis on 10+ binaries at once, pass an active
file to a dumb subagent to work on, and a lot of the other things that we do here ^..^

###### how does this talk to projects while avoiding the lock

for the two people on earth who will have this question, we use a separate single process for managing everything related to 
projects; it owns the handles for the official ones and such.

###### misc

while the panel looks like it has multi-acct support, it does not and will not ever for a single commercial license. 

### on context window size

With every tool enabled (not really the intended use case but go for it), this can use up to, like, 40k of context on just
the tool schema. OpenAI's API will cache this w/ a 30min TTL and not charge you for it past the first ingest, apparently. 
Given how obtuse they are w/ that stuff it's difficult to validate. 

Typically, I use this with a much smaller feature set enabled; It's 2 clicks to disable a toolset at runtime. 

There is a reduced toolset option which exposes 15 common lifecycle/control calls to modern MCP clients and 13 to legacy
clients. One of them brokers access to every other enabled toolcall. Changing this option requires saving the configuration
and restarting the service.

I frankly don't think this matters and we may be getting a bit lost in the sauce, but as I understand people feel strongly about this. 

- bn_tools
- bn_analysis_session_create (modern MCPs)
- bn_analysis_session_close (modern MCPs)
- bn_local_project_list
- bn_local_project_file_list
- bn_open_item_open
- bn_open_item_close
- bn_binary_view_open
- bn_analysis_status
- bn_analysis_update_and_wait
- bn_binary_view_save
- bn_job_list
- bn_job_info
- bn_job_result
- bn_job_cancel

### feature wishlist

* I'd love if the mac menu bar item worked for remote servers, packaging there needs thought about 
* It's not a lot of work to do something like the code-mode MCP ida has, I just disagree w/ that design. Could be a toggle.
* 

##### LLM disclosure

yes. graphics were made by hand tho. 

---

#### security

This project is in no way a security boundary; binaryninja's own official policy itself doesn't treat its own core as a security 
boundary, and in general if you are exposing this on the open web expect to have a bad time. 

While I've tried fairly hard to ensure the unauthenticated surface doesn't have unreasonable bugs, please use tailscale if you need this on WAN,
it is completely free. 

Additionally, assume an MCP token could achieve code exec through binaryninja itself via toolcalls and secure systems accordingly <3.
I welcome security-related bug reports but this project should never run at the edge of a network.

---

#### license

This is licensed under BSD-3C. Please note [LLMs were used](#llm-disclosure).
