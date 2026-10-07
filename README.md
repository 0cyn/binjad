![logo](.github/img/logo.png)

<p align="center">
  <a href="#install">install</a> | <a href="#restart-stop">restart</a> | <a href="#config">config</a> 
  <br><a href="#update-binjad">updating binjad</a> | <a href="#swapping-binaryninja-versions">Swapping Binary Ninja version</a>
</p>

This is an **UNOFFICIAL** HTTP MCP daemon for BinaryNinja **Commercial Edition** that offers "a few" things the official doesn't, and fixes some of my gripes
trying to work with the official one. It's designed for fully autonomous parallel work with multiple agents at scale, not 
single agent guided analysis.

> "ALPHA": This is currently in the process of being shaped and I want feedback from other people's workflows. I do a few specific 
> things with my tooling and want to make this also good for other people's use cases. Reach out in the issues even if it's a stretch. 

> This is probably a little buggy right now :P bear with me.

> I am not currently an employee or affiliate of Vector 35 and this project is not associated with them in any way.

This runs indefinitely in the background without binaryninja open. Config is done via a web panel, 
and the daemon can be controlled from its macOS menu bar item or through `brew services`. You will need a 
Commercial binaryninja license since that's required for using BinaryNinja headlessly. 


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
For frontier things, it means you're not attaching a dice roll with a price tag on failure to menial binaryninja tasks. I've watched "AGI level" models fail
to write a script interacting w/ binaryninja's api over 10 times in a single task with docs on hand. 

Additionally, part of the reason I built this was because I've had a 112-core local box i've been dying
to use for analysis runs while doing the actual work on my main laptop. It's a cool way to outsource the analysis
while not working over VNC; I've wanted to do that for years, and an MCP is almost the only way of doing that that actually
makes sense outside of insane enterprise automation. 


### some other stuff

* Markdown and JSON project file readers. Agents loooove putting these in Projects, so I just made it first-class behavior.
* it's been tuned to work with smellier local models; several Qwen 3.8 27b agents on a 5090 doing binary analysis in parallel was a common use case while testing
* and on that note, a lot has been done to make sure it doesn't obliterate context
* Web Panel :thumbsup:
* There is a menu bar for macOS w/ a few daemon controls. 

![img.png](.github/img/menubar.png)


> Caveat of project work: Due to a binaryninja limitation, if you are running the server locally, having a project in GUI open in any way holds
> a 'lock' on the project, which will result in certain toolcalls that modify projects failing.


### install

binjad has to have a binaryninja versioned release installed because it's linked to binaryninja. 
homebrew lets us have our own versioning inside of this. 

so, installing an update _to binjad_ (e.g. i fix a broken toolcall) looks like `brew update && brew upgrade binjad`, however
if you swap to a different binaryninja build you'll need to install a different @version of the package. 

For this reason, it's ideal that you stay on a BinaryNinja Stable release, but dev builds are supported.

current stable:
```shell
# Check your bn version in the app and install appropriate one
# Current Stable:
brew install 0cyn/tap/binjad@6.0.10601
brew services start binjad

# Set up the daemon, grab the token, etc
open http://127.0.0.1:8712/portal  # macOS
```

There is a rube-goldberg set of github actions scripts set up to try and get dev builds out automatically
as soon as they're published on binaryninja-api. If anything changes on API that requires updating actual
code in this project presumably something will break and it'll require manual intervention, but for most
dev versions a build should be available within about an hour. 

installing for any dev including/after this one: 
``` 
brew install 0cyn/tap/binjad@6.1.10811
brew services start binjad

# Set up the daemon, grab the token, etc
open http://127.0.0.1:8712/portal  # macOS
```

On macOS, You'll be prompted by macOS for keychain password on daemon startup and acct creation since we store keys, login info, and such there. There is also a
menu bar item that allows you to stop/start/restart the daemon, hot-toggle toolkits, view runtime status, and hop back to the portal.

#### Swapping BinaryNinja versions

``` 
brew services stop binjad
brew uninstall 0cyn/tap/binjad@<OLD_VERSION>
brew install 0cyn/tap/binjad@<NEW_VERSION>
brew services start binjad

# technically, uninstalling is optional; you could `stop binjad@<OLD_VERSION>` and 
# then `start binjad@<NEW_VERSION>` but it'd require you to qualify the version every time,
# :p better to just do this
```

!!! `brew upgrade binjad` is for binjad bugfixes, not updating the linked build. 

### update binjad 

(for bugfixes and features)

``` 
brew update
brew upgrade binjad
brew services restart binjad
```

### config

The default Binary Ninja locations are `/Applications/Binary Ninja.app` on macOS and `~/binaryninja` on Linux.

If you have it installed elsewhere, set `binary_ninja.installation_dir` in yr config. Once installed, start the service,
head to http://127.0.0.1:8712/portal, and create the account.

You can configure everything from the panel henceforth. 

Config locations:

* macOS: `~/Library/Application Support/binjad/config.json`
* Linux: `$XDG_DATA_HOME/binjad/config.json`, or `~/.local/share/binjad/config.json` when `XDG_DATA_HOME` is unset

### restart/stop

```shell
# restart the daemon
brew services restart 0cyn/tap/binjad
# stop it
brew services stop 0cyn/tap/binjad
# start it again
brew services start 0cyn/tap/binjad
```

### connecting

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




### exposing on LAN

I run this on a server locally, wired up to tailscale, with nginx reverse-proxying crap to the daemon. 

During setup, I configured remote options, handed it the tailscale my agent can reach it from (for file uploads/downloads),
and set it to run on `8713`. nginx then forwards the traffic to it. presumably if you need this on lan you can do
something similar to this. 

``` 
user@host:~$ cat /etc/nginx/sites-enabled/binjad
server {
    listen 0.0.0.0:8712;
    server_name _;

    client_max_body_size 4g;
    client_body_timeout 3600s;
    gzip off;

    location / {
        proxy_pass http://127.0.0.1:8713;
        proxy_http_version 1.1;

        proxy_set_header Host $http_host;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header Connection "";

        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;

        proxy_request_buffering off;
        proxy_buffering off;
        proxy_cache off;

        proxy_connect_timeout 10s;
        proxy_send_timeout 3600s;
        proxy_read_timeout 3600s;
    }
}
```



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
<p align="center"><sub>prompt + initial exploration</sub></p><br>

![img.png](.github/img/demo2.png)
<p align="center"><sub>a subagent digging through the diff</sub></p><br>

![img.png](.github/img/demoresult.png)
<p align="center"><sub>Digging through the generated report using `bntextviews` (unchecked, probably pretty close, but you've got hotlinks to make that validation so much easier on your end.)</sub></p><br>


Use this with the `bntextviews` plugin to allow your agents to write markdown/json content into projects you can then display in
BinaryNinja with a nice document reader. It's good!

I've found Qwen 3.8 27b on a 4-bit quant to be very capable of everything this toolkit exposes. Docs have been tuned to
help lower-spec models through trickier things.

> fun challenge: figure out how many of these vulnerabilities are actually exploitable ^..^

![img.png](.github/img/panel.png)


### commercial license

BinaryNinja Commercial licenses are allowed one active MCP token and one account.

Usage by multiple individuals and/or usage in containerized deployments of infra is disallowed by Binary Ninja's license terms (afaik).

You are intended to use this project on local hardware, by yourself. If you're trying to use this project for anything
other than that, you should probably reach out to their support and ensure you're working within your current license, or 
adjust your license agreement with them accordingly. 

I am not responsible for you misusing this to break the law. 

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

Basically all of the model-facing documentation needs rewritten by a person before I'm truly happy with this, LLMs are just
not good at that sort of thing. Work has been done to make sure it's functional, but the more this is improved, the cheaper
the models this can be used with. 

* I'd love if the mac menu bar item worked for remote servers, packaging there needs thought about 
* It's not a lot of work to do something like the code-mode MCP ida has, I just disagree w/ that design. Could be a toggle.
* api script documentation tool

Please thumbs-up the [Windows Support]() issue if you need that.

##### LLM disclosure

yes. graphics were made by hand tho. this may result in there being a few areas of the codebase I'm not intimately familiar with and the sort
of problems that arise from that. I did want a project to experiment w/ the tech on, though. It does seem useful as a 
productivity tool, a future where I don't have carpal tunnel despite my workaholic nature sounds nice,
but has tradeoffs that are going to require some learning. Don't expect LLM commits on my previously published
work at this time. 

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
