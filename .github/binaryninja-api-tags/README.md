# Binary Ninja API tag state

The hourly GitHub Actions monitor compares these records with release tags from
`Vector35/binaryninja-api`.

Each file contains one tag and its resolved commit:

```text
<channel>/<major>.<minor>.<build> <40-character commit>
```

Starting from the reviewed `dev/6.1.10811` baseline, the monitor opens one pull
request for the oldest unprocessed development tag. This serial order ensures
that every later official development release can receive an exact formula.
It targets the `dev` branch and updates that branch's `dev.txt` state file and
the `vendor/binaryninja-api` submodule. Stable API updates are selected and
applied manually on the `stable` branch.

Tag names are release events. A newer tag still causes a pull request when it
points to the same API commit as an earlier tag. Only one source proposal is
active at a time; merge or remove it before the next tag can advance.

Delete an abandoned automation branch if the monitor must propose that tag
again.
