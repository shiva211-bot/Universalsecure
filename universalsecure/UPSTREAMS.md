# Upstream projects

Universalsecure was requested as a local-code tool informed by these three projects:

| Project | Upstream | Role in this release |
| --- | --- | --- |
| PentAGI | <https://github.com/vxcontrol/pentagi> | Pinned source under `upstreams/pentagi/`. Its autonomous testing workflow is not launched by this CLI. |
| Security Audit Skill | <https://github.com/cloudflare/security-audit-skill> | Pinned source under `upstreams/security-audit-skill/`; reference for staged, evidence-oriented review. |
| Strix | <https://github.com/usestrix/strix> | Pinned source under `upstreams/strix/`. Its active testing workflow is not launched by this CLI. |

Each project is a Git submodule rather than copied source. Its own license and history remain with the upstream repository. Review the license and terms in each pinned submodule before redistributing or modifying that project's files. No license has been assigned to the Universalsecure wrapper yet.

## Integration boundary

The initial CLI performs local source inspection only. It does not invoke PentAGI or Strix, run a target application, generate or execute exploit payloads, or contact a remote host. The submodules preserve the requested source references without presenting active testing as a local static scan.
