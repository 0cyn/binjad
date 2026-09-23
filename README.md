### binja'd

<super>this readme was fully written by a human, u can read it! <3</super>

[install](#install)

This is an **UNOFFICIAL** MCP for binaryninja Commercial that offers "a few" things the official doesn't, and fixes some of my gripes
trying to work with the official one. It's designed for fully autonomous parallel work with multiple agents, not 
single agent guided analysis.

It's built so you can run it on your local machine, permissively or limited, 
or throw it on a compute server and work on remote projects with your agents running on a separate machine that never needs to run binaryninja. 

It's also centered around Projects, which tends to force better organization and allows the daemon to keep track of
everything. 

> Beta release! This may break with different setups. Let me know in the Issues or bother me on messaging platforms if you have me. 
> I want to know what use cases you have for this and what tools you need to do those things. 

I am not an employee or affiliate of Vector 35 and this project is not associated with them in any way.

### big features

* Project support
* Concurrent sessions (there is not an "active view" paradigm)
* KernelCache, SharedCache, Debugger support
* Diffing
* binaryninja:// url creation
* Feature parity w/ official MCP; all of the toolcalls from the official are present too
* Files are loaded in individual processes, so crashes do not destroy other unsaved work.
* Project support is forced, so local LLM agents can work fully sandboxed. 

>  "Extract these two KDKs from their dmgs, add them to a project named 'KDKs', then use Qwen subagents w/ binjad to
> diff every file in them and report anything that looks like a vulnerability fix. Save your results to a markdown file
> within that project, and generate binaryninja URL links to all mentioned functions. Present the contents of the file to
> me afterwards"

I've found Qwen 3.8 27b on a 4-bit quant to be very capable of everything this toolkit exposes. Docs have been tuned to 
help lower-spec models through trickier things. 

### some other stuff 

* Load balancing in the event you want to run this on a server
* Markdown and JSON project file readers. Agents loooove putting these in Projects, so I built an API that makes them nicely parseable. 
* A nice non-claudeslop panel you can use to fuck w/ settings, issue tokens for your different agents, etc.
* it's been tuned to work with smellier local models; several Qwen 3.8 27b agents on a 5090 doing binary analysis in parallel was a common use case while dogfooding
* and on that note, a lot has been done to make sure it doesn't obliterate context
* ^ you can disable tools/plugin support you know your agents will not need to cut context even further
* Web configuration API :thumbsup:

### install 

installation is currently done through homebrew. 

keychain is gonna ask for your password because we store auth stuff in the system keychain. 

macOS is the only supported platform at this time, with other OSes being in the pipeline
(You may already find WIP code littered around. It's not a design limitation. ) 

Please thumbs-up the [Windows Support]() or [Linux Support]() issues if you need it on these platforms. 

```

```

### what prompted this

i put this together primarily because agents trying to use the official one either couldn't, due to issues 
as they deferred tasks or attempted concurrent work, or when they did successfully manage to use it, would frequently
have issues with:

* A crash in binja, a C++/Qt program (they do that, i still love u c++), wiping out hundreds of views
* Hundreds of unsaved views existing in the first place with no incentive for models to clear them out 
* Constantly focusing the UI ([watch it interrupt my demo several times](https://x.com/arm64e/status/2096729422468362312?s=20))
* Frequently after sessions views would become unsavable with locking issues
* Zero encouragement to the model to save analysis
* On some common toolcalls, incredibly token-heavy output.

in general i think the philosophy of having everything, even a headless instance, tied to UI state is not very 
conducive to the types of work modern frontier/even consumer LLM kit can facilitate. 

i am not using an MCP because i want to open a terminal and have it open a binaryview in an app and tell me what a function does. 
i want to sit down, tell my 5090 to diff a bunch of things in a large dataset, tell me what it thinks changed between versions,
and give me links to the interesting shit. 

### commercial

Commercial licenses are allowed one active MCP token at a time, w/ all tokens being all-access. If you think that is 
dumb or whatever, 
* it makes design and setup way easier, 
* binaryninja's license has terms, and 
* Ghidra is free and unlicensed; you have the ability to materialize infinite code w/o anyone being mad at you. 

There isn't really permission gating beyond globally disabling toolcalls that interact with local files, because if
you need that for some reason you are probably violating the product's license. sry!

---

### design schtuff

###### mandatory projects

Projects are mandatory w/ this tooling. This was an explicit decision; it forces models to not fan out across a filesystem
and just by default keep things much more organized. When running on a server, it also just gives us a nice obvious place to store files and .bndbs.

It also allows us to offer MCP tools to sandboxed agents that 

> Caveat of this: Due to a binaryninja core limitation, if you are running the server locally, having a project in GUI open in any way holds 
> a 'lock' on the project, which will result in certain toolcalls that modify projects to fail.

---

###### obviously

there was _heavy_ llm assistance with the development of this, although there was also very heavy steering and spec-work beforehand; 

I'm comfortable enough with the quality and design of it to ship to others, i've deadass read through every file and written parts myself, i've worked with the APIs involved for years,
but it should be treated like it was written by an LLM. 

the workflow on this looked like about a week of sketching out a very stable MVP, and then 2-3 weeks of reading the code,
remolding things to be a lot less insane, more performant, etc. I do think it's very important that you know
exactly how the thing you're trying to make exist should be written or the entire thing is unsustainable :) and i've 
been doing projects like this for long before LLMs. yap over

#### security

This project is in no way a security boundary; binaryninja's own official policy itself doesn't treat its own core as a security 
boundary, and in general if you are exposing this on the open web expect to have a bad time. While I've tried fairly hard
to ensure the unauthenticated surface is airtight, like, just use tailscale or something please. It's free. 

In an Enterprise context, please assume even a non-admin token could achieve code exec through binaryninja itself via
toolcalls and secure systems accordingly <3. I welcome security-related bug reports but this project should never run
at the edge of a network. 

---

### prs

* if your changelog was written by an LLM i am automatically closing the PR and banning you from the repository. 
* no LLM text that gets presented to a model's context, please (e.g. toolcall docs). Even with frontier models this tends to just progressively degrade and balloon in size. Care in this department makes things work well. 

