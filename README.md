![logo](.github/img/logo.png)

<p align="center">
  <a href="#install">install</a> | <a href="#restart-stop">restart</a> <br>
<a href="#why-is-this-better-than-having-an-agent-write-api-scripts">why is this better than having an agent write API scripts</a>
</p>

This is an **UNOFFICIAL** HTTP MCP daemon for BinaryNinja **Commercial Edition** that offers "a few" things the official doesn't, and fixes some of my gripes
trying to work with the official one. It's designed for fully autonomous parallel work with multiple agents at scale, not 
single agent guided analysis.

This runs indefinitely in the background without binaryninja open. Config is done via a web panel, 
and the daemon can be controlled from its macOS menu bar item or through `brew services`. You will need a 
Commercial binaryninja license since that's required for using BinaryNinja headlessly. 

> Beta release! This may break with different setups. Let me know in the Issues or bother me on messaging platforms if you have me. 
> I want to know what use cases you have for this and what tools you need to do those things. If you're willing to spam
> me with issues when things break, we can turn this into the best tool in industry for this sort of work. 

I am not currently an employee or affiliate of Vector 35 and this project is not associated with them in any way.

![img.png](.github/img/menubar.png)

### big features

* Project support
* Concurrent analysis (there is not an "active view" paradigm)
* KernelCache, SharedCache, Debugger support
* Diffing
* Mach-O, ELF, and PE header/dependency parsing
* binaryninja:// url creation
* Feature parity w/ official MCP; all of the toolcalls from the official are present too
* Files are loaded in individual processes, so crashes do not destroy other unsaved work.
* Project support can be forced, so local LLM agents can work fully sandboxed. 
* Categories of tools can be disabled to save context. 
* Optional "reduced mode" that reduces the list of force-advertised toolcalls to 6, if you need that. Still allows querying tools and using all of them. 

I find dumping more of the toolset into context helps gently guide consumer/prosumer models towards solutions without
heavy-handed guidance needed. 

> "Extract these two KDKs from their dmgs, add them to a project named 'KDKs', then use Qwen subagents w/ binjad to
> diff every file in them and report anything that looks like a vulnerability fix. Save your results to a markdown file
> within that project, and generate binaryninja URL links to all mentioned functions. Present the contents of the report to
> me afterwards"

Use this with the `bntextviews` plugin to allow your agents to write markdown/json content into projects you can then display in
BinaryNinja with a nice document reader. It's good!

I've found Qwen 3.8 27b on a 4-bit quant to be very capable of everything this toolkit exposes. Docs have been tuned to 
help lower-spec models through trickier things. 

### some other stuff 

* Load balancing so one subagent doesn't brick the others
* Markdown and JSON project file readers. Agents loooove putting these in Projects, so I just made it first-class behavior. 
* Recursive local-directory imports and safe adoption of outside-root projects into configured project roots.
* A nice non-claudeslop panel you can use to fuck w/ settings, handle auth, etc.
* it's been tuned to work with smellier local models; several Qwen 3.8 27b agents on a 5090 doing binary analysis in parallel was a common use case while testing
* and on that note, a lot has been done to make sure it doesn't obliterate context
* Web configuration API :thumbsup:

![img.png](.github/img/panel.png)

> Caveat of project work: Due to a binaryninja limitation, if you are running the server locally, having a project in GUI open in any way holds
> a 'lock' on the project, which will result in certain toolcalls that modify projects failing.


### install note

installation is currently done through homebrew. 

macOS is the only supported platform at this time, with other OSes being in the pipeline
( You may already find WIP code littered around. It's not a design limitation. ) 

Once installed, start the service, head to http://127.0.0.1:8712/portal, and create the account. You'll be prompted by macOS
for keychain password on daemon startup and signup since we store keys, login info, and such there. There is also a
menu bar item that allows you to stop/start/restart the daemon and hop back to the portal. 

You can configure the daemon through the web portal or by manually editing `~/Library/Application\ Support/binjad/config.json`

Please thumbs-up the [Windows Support]() or [Linux Support]() issues if you need it on these platforms. 

#### install

```shell
INSTALLED_VERSION=/Applications/Binary\ Ninja.app/Contents/MacOS/bnpython3 -c "print(__import__('binaryninja').core_version().split('-')[0])"
brew install 0cyn/tap/binjad@$INSTALLED_VERSION
brew services start binjad
# open configuration panel to set it up and get an MCP token. 
open http://127.0.0.1:8712
```

#### restart/stop

```shell
# restart the daemon
brew services restart binjad
# stop it
brew services stop binjad
# start it again
brew services start binjad
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

### commercial license

Commercial licenses are allowed one active MCP token and one account.

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

With every tool enabled (not really the intended use case but go for it), this can use up to 40k of context on just
the tool schema. OpenAI's API will cache this w/ a 30min TTL and not charge you for it past the first ingest, apparently. 
I haven't experimented with that really. 

Typically, I use this with a much smaller feature set enabled; It's 2 clicks to disable a toolset at runtime. 

There is a reduced toolset option which exposes 15 common lifecycle/control calls to modern MCP clients and 13 to legacy
clients. One of them brokers access to every other enabled toolcall. Changing this option requires saving the configuration
and restarting the service.

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

### "why is this better than having an agent write API scripts"

There's a lot of discussion on this topic right now. Especially around context usage, etc. So here's the blogpost from
me on the topic. 

With a frontier model, ideally you're using both of these in tandem; This gives models a framework for a simple prompt that won't result in crazy directory sprawl. 

I might have an entire OS filesystem's set of binaries in a project, and instead of having to manually include the long
list of instructions on how to use that each time I can just say "use the iOS IPSW dump project in binja'd", and it'll
reuse existing bndbs. 

Another strong use case I've found with this is with local LLMs (Qwen 3.8 27b is a fav), which can definitely perform RE
tasks (and actually get there much faster than frontier models), but which I am absolutely not letting run arbitrary
python scripts on my system. This gives them literally every tool they need to analyze, organize, perform RE, annotate, and perform 
generic VR, without requiring handing a cheap model an execute_python_script tool.

You can have a frontier model w/ full API scripting access and sandboxed subagents that operate on view handles the orchestrator
hands them. Observed models have done this pretty consistently, naturally without needing much guidance to do so, resulting in 
cheaper work with a lot less paid compute usage. 

`<opinion>`
This is a particular gripe I have with IDA's whole official "code mode" (read: completely useless?) MCP. Using proper
context management, the tools can serve as a framework to guide a model through whatever you asked it to do, _and_ as a sandbox
to keep agents that are aligned just fine from accidentally doing something really stupid. And in a case where a SOtA model 
doesn't need guidance, why on earth does it need an MCP to execute ida scripts. 

from their blog: 
> We also tested Qwen 3.8 27B, which can run (quantized) on a single consumer GPU (24GB NVIDIA RTX 3090). This class of models can perform reverse engineering tasks, but tends to get stuck and overthink, so you need a more hands-on approach. That being said, a minimal harness like Pi and the small footprint of the IDA MCP tools make a suitable combination for consumer hardware where prefill speeds are relatively low.

maybe it's because you're just handing it a script runner bro ;_; IDK man. We're not always going to have these
3T param models available this cheap.
`</opinion>`

##### LLM disclosure

A lot of work has gone into making this solid on my setup, a lot of care went into the architecture and design of this, any
graphics you see were made with AI (Adobe Illustrator,) and I do give a fuck about this working. This was not oneshotted
in a week. But also yes, heavy LLM usage occurred for code. It's an MCP man.

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
