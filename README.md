### binja'd

<super>this readme was fully written by a human, u can read it! <3</super>

>  "Extract these two KDKs from their dmgs, add them to a project named 'KDKs', then use low cost subagents w/ binjad to
> diff every file in them and report anything that looks like a vulnerability fix. Save your results to a markdown file 
> within that project." 

This is an **UNOFFICIAL** MCP for binaryninja Commercial that offers "a few" things the official doesn't, and fixes some of my gripes
trying to work with the official one. It's designed for fully autonomous, parallel work, not guided analysis.

It's built so you can run it on your local machine, permissively or limited, 
or throw it on a compute server and work on remote projects with your agents running on a separate machine that never needs to run binaryninja. 

It's also centered around Projects, which tends to force better organization and allows the daemon to keep track of
everything. 

> Beta release! This may break with different setups. Let me know in the Issues or bother me 

I am not an employee or affiliate of Vector 35 and this project is not associated with them in any way.

### big features

* Project support 
* KernelCache, SharedCache, Debugger support
* Diffing
* Feature parity w/ official MCP; all of the toolcalls* are present too
* \*Concurrent sessions (there is not an "active view" paradigm)
* Files are loaded in individual processes, so crashes do not destroy other unsaved work.
* Support for local or remote MCP serving. (remote works via file uploads, agent must be able to POST to a dynamic URL.)

### some other stuff 

* Load balancing in the event you want to run this on a server
* Markdown and JSON project file readers. Agents loooove putting these in Projects, so I built an API that makes them nicely parseable. 
* A nice non-claudeslop panel you can use to fuck w/ settings, issue tokens for your different agents, etc.
* it's been tuned to work with smellier local models; several Qwen 3.8 27b agents on a 5090 doing binary analysis in parallel was a common use case while dogfooding
* and on that note, a lot has been done to make sure it doesn't obliterate context
* ^ you can disable tools/plugin support you know your agents will not need to cut context even further
* Web configuration API :thumbsup:

### commercial

Commercial licenses are allowed one active MCP token at a time, w/ all tokens being all-access. If you think that is 
dumb or whatever, 
* it makes design and setup way easier, 
* binaryninja's license has terms, and 
* Ghidra is free and unlicensed; you have the ability to materialize infinite code w/o anyone being mad at you. 

### enterprise (Collaboration Client)

If you have an enterprise license and server for binaryninja, this project has WIP support for enterprise clients as well. 
Feedback from people using Ultimate/Enterprise would be appreciated. 

The general design model is that there are admin accounts that can manage the server and use invasive tools, 
and self-serve accounts that just exist so engineers can issue an MCP token associated with their collaboration account.
Additionally, you can configure load balancing per-user 

The use case envisioned with this is throwing it on some huge compute server and allowing engineers to grab MCP tokens
from that server and do bulk autonomous analysis/RE without requiring them to have adequate local compute, but doing
it in a way that doesn't sacrifice provisioning, allow one guy to hog the entire server, etc. 

If you're working w/ collaboration client, reach out on [This Issue](link) and let me know what magical use case 
you're envisioning from this.

---

### design notes

###### mandatory projects

Projects are mandatory w/ this tooling. This was an explicit decision; it forces models to not fan out across a filesystem
and just by default keep things much more organized. When running on a server, it also just gives us a nice obvious place to store files and .bndbs.

It also allows us to offer MCP tools to sandboxed agents that 

> Caveat of this: Due to a binaryninja core limitation, if you are running the server locally, having a project in GUI open in any way holds 
> a 'lock' on the project, which will result in certain toolcalls that modify projects to fail. 

---

###### obviously

there was _heavy_ llm assistance with the development of this, although there was also very heavy steering and spec-work beforehand; these things are still kinda bad at design and usability decisions. 


I'm comfortable enough with the quality and design of it to ship to others, i've read through things and written parts myself, i've worked with the APIs involved for years,
but it should be treated like it was written by an LLM. 

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

