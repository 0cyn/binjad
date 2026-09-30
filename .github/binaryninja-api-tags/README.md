# Binary Ninja API tag state

The hourly GitHub Actions monitor compares these records with release tags from
`Vector35/binaryninja-api`.

Each file contains one tag and its resolved commit:

```text
<channel>/<major>.<minor>.<build> <40-character commit>
```

The monitor opens one pull request for the newest unprocessed tag in each
channel. The pull request updates the matching state file and the
`vendor/binaryninja-api` submodule.

Tag names are release events. A newer tag still causes a pull request when it
points to the same API commit as an earlier tag.

Delete an abandoned automation branch if the monitor must propose that tag
again.
