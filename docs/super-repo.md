# Building a Super-Repo

A super-repo is one directory that holds everything that makes up a single
application: all of its code repos checked out side by side, plus the
infrastructure and pipeline code that deploys it. It is what you point
`lucy scan --target` at.

```text
example-super-repo/
  CMDB_ID.txt              # optional: "APP001 | Example Application"
  example-api/             # backend repo
  example-web/             # frontend repo
  example-worker/          # batch jobs repo
  example-infra/           # terraform / kubernetes / pipelines
  docs/                    # optional: architecture notes, threat model
```

## Why bother

Most applications are not one repo. The backend, the frontend, the batch
jobs, and the infrastructure live in separate repos, and most scanners look
at them one at a time. That misses the seams, and the seams are where a lot
of real vulnerabilities live: a frontend that trusts a header the backend
never validates, a security group that exposes an admin endpoint the
application code assumed was internal, a pipeline that runs code from an
unpinned dependency.

Scanning the super-repo means:

- **The whole application is reviewed as one thing.** Cross-repo problems
  are findable because both sides of the seam are in view. LUCY's sweep
  lanes exist specifically to chase patterns across repo boundaries.
- **Coverage is measured against the whole application.** The file census,
  the every-file-opened check, and the certification all apply to the full
  super-repo, not one repo at a time.
- **You get one report per application**, which matches how risk is
  tracked, instead of a pile of per-repo reports someone has to stitch
  together.

One super-repo should be one application. Don't combine unrelated
applications into a single super-repo; scan them separately.

## How to build one

1. Make a directory and clone every repo that belongs to the application
   into it, side by side. Include the infrastructure repos (Terraform,
   Kubernetes, pipeline definitions), not just application code.
2. Check out the branch you actually deploy from in each repo. Note that
   LUCY scans the working tree as it sits on disk, not git history:
   uncommitted edits and untracked files are included, and stashed or
   unpulled work is invisible. For a scan meant to represent a release,
   make every repo a clean checkout (`git status` clean) of the commit you
   care about.
3. Optionally add a `CMDB_ID.txt` at the top level with your application's
   ID and name (`APP001 | Example Application`). The report will be named
   after it.
4. Optionally add documents that explain how the application works:
   architecture notes, data flow diagrams, a threat model, operational
   runbooks. LUCY reads them as context. Plain text and markdown work best.

That's it. LUCY copies the whole directory into a disposable workspace and
scans the copy; your super-repo is never modified (this is verified by
hash at the end of every run).

## What to leave out

- **Your prior-findings file.** It must live OUTSIDE the super-repo; the launcher
  refuses to run if it's inside.
- **Secrets.** The scan looks for committed secrets, so anything present
  will be found and reported, but don't add live credentials just to be
  thorough.
- **Build artifacts and vendored dependencies** (`node_modules`, `dist`,
  `build`). Common ones are skipped automatically, but leaving them out
  keeps the census and the cost estimate honest.
- **Old scan results.** Findings never belong inside the thing being
  scanned.

## Size and cost

Cost and time scale with lines of code. Get a number before spending
anything:

```bash
lucy scan --target ~/code/example-super-repo --results ~/lucy-results --estimate-only
```

The estimate reports a workload-specific time and cost range before any
review work begins.
