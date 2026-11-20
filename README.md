# github-core-clone-01

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/soluska/github-core-clone-01/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/soluska/github-core-clone-01/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A GitHub-compatible git forge in a single dependency-free Node server. One in-memory store backs four surfaces: the REST v3 API (repositories, branches, commits, contents, issues, comments, labels, pull requests and merges), git smart HTTP with protocol v0 and v2 (info/refs, ls-refs, upload-pack and receive-pack, with a pure-Node packfile reader/writer that resolves ofs/ref deltas and thin packs), GraphQL v4 (the documents gh and github-mcp-server send, executed by a hand-written parser with opaque stable global ids), and a streamable-HTTP MCP endpoint whose tools mirror the REST operations. No npm dependencies, no git binary, no disk state: object storage, refs and issues all live in memory, and timestamps derive from a deterministic clock so replays are byte-stable.

## Run it

```sh
MAKEFUN_ENV_URL=http://127.0.0.1:8080 node --experimental-strip-types main.ts
```

The entry registers its ephemeral port with the env at `$MAKEFUN_ENV_URL`, serves until the env says the trial is done, and exits 0. Point any git client at it with a bearer token (`git -c http.extraHeader="Authorization: Bearer <token>" clone http://<host>/<owner>/<repo>.git`).

---

<sub>Entered on [make.fun](https://make.fun/?ref=esagh3na&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
