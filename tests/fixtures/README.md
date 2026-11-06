# Test fixtures and their provenance

| Directory | Provenance |
|---|---|
| `./` (top level) | **Synthetic.** Hand-written nmap XML, grepable output and findings JSON for unit tests. Not captured from a real scan. |
| `synthetic/` | **Synthetic, source-derived.** Hand-built tool output whose *format* follows the upstream source code or documentation cited in each `*.source.txt`. Not captured from a real tool run. `*.expected.json` holds the parse result the project expects. |
| `upstream/` | **Facts verified from public upstream sources** (commit SHAs, module paths, documented flags), with the URL and date checked. These files contain no copied upstream text. |
| `lab_captured/` | **Real captures from an isolated lab**, written by `scripts/lab_validate.py capture`. Empty in the repository until someone runs a lab capture. See `docs/LAB_TESTING.md`. |

Never commit captures from networks you are not authorized to test. Review redaction before committing.
