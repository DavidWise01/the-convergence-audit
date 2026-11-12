# ROOT0 Convergence Scout — observation-only internet crawler

**Distinct from NOM.** This is an isolated new instrument in `the-convergence-audit`. The historical audit findings and NOM's two-host restrictions are unchanged.

It crawls a bounded set of public pages, subject to host allowlists, `robots.txt`, per-host delays, maximum depth/pages, a 512 KB response limit and a ten-second network timeout. It skips forbidden, unreachable or non-HTML pages. It never logs in, bypasses blocks, downloads private material, performs model inference, or interprets resemblance as copying.

Configure `crawler/config.json` to choose public hosts, seed pages, and distinctive patterns. Additional public hosts may be added; `www.reddit.com` can be included only where its current robots rules allow reading. Discovery follows links within configured hosts rather than trying to index the entire web.

## Run locally

```sh
python -m unittest discover -s crawler -p 'test_*.py' -v
python crawler/crawl.py --max-pages 20
```

Matches append to `crawler/observations.jsonl`. Each record contains observed time, public URL, host, matching literal phrase, a digest of the extracted page text, and the classification `UNREVIEWED_CONVERGENCE_CANDIDATE`. It deliberately does **not** duplicate source text or assert copying, attribution, causation, independent origins, or verified research. An unchanged page/phrase combination is de-duplicated; a changed page produces a new observation. The ledger rejects malformed prior lines.

The optional scheduled workflow `convergence-scout.yml` runs every twelve hours if GitHub Actions are enabled and the repository allows workflow writes. It commits newly appended observations only. The JSONL is application-level append-only with Git history, not a cryptographic guarantee against repository administrators rewriting history. Runtime success and the first remote crawl require independent GitHub Actions verification.

**Next phase:** review candidate observations against historical ROOT0 snapshots. Keep shared terminology distinct from independent evidence. The pre-existing convergence audit has not been reclassified.
