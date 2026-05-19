---
name: incident-analysis
description: "Perform security incident analysis using Elasticsearch and Ghidra MCP tools. Use when: investigating incidents, hunting for IOCs, analyzing malware, building attack timelines, identifying attacker TTPs, forensic artifact collection, threat investigation, compromise assessment."
argument-hint: "Describe the incident scope, known IOCs, or timeframe to investigate"
---

# Incident Analysis

Systematic incident investigation using Elasticsearch for log/event analysis and Ghidra for binary/malware reverse engineering. Produces an evidence-backed incident report with IOCs, attacker TTPs, and a reconstruction of what happened.

## Procedure

### Phase 1 — Reconnaissance & Scoping

1. **Discover available data** before querying:
   - Use `mcp_elasticsearch_list_indices` to enumerate all available indices
   - Use `mcp_elasticsearch_get_mappings` on promising indices to understand field names and data types
   - Identify which index patterns contain security-relevant data (logs, endpoint events, network flows, authentication, DNS, file events, process events)
2. **If Ghidra is loaded with a binary**, use `mcp_ghidra_list_functions`, `mcp_ghidra_list_imports`, and `mcp_ghidra_list_exports` to get an initial overview of the sample

### Phase 2 — Broad Threat Hunting

Query Elasticsearch across multiple event categories to surface suspicious activity. Use ES|QL via `mcp_elasticsearch_esql` for all queries.

3. **Process events** — Look for unusual process executions, suspicious parent-child chains, LOLBins, encoded commands, script interpreters spawning unexpected children:
   - PowerShell with `-enc`, `-nop`, `-w hidden`, `IEX`, `Invoke-Expression`, `DownloadString`
   - `cmd.exe` spawning `whoami`, `net`, `nltest`, `dsquery`, `certutil`, `bitsadmin`, `mshta`, `regsvr32`, `rundll32`
   - Unusual processes running from `\Temp\`, `\AppData\`, `\ProgramData\`, `\Users\Public\`
4. **Network events** — Search for connections to unusual external IPs/domains, beaconing patterns, high-volume data transfers, connections on non-standard ports
5. **File events** — Look for file creation in suspicious directories, dropped executables, scripts, renamed system binaries, archive extraction
6. **Authentication events** — Search for brute-force patterns, lateral movement (type 3/10 logons), privilege escalation, unusual service account activity, logon outside business hours
7. **Registry / persistence** — Look for Run keys, scheduled tasks, services, WMI subscriptions, startup folder modifications
8. **DNS queries** — Search for domain generation algorithm (DGA) patterns, tunneling indicators, queries to known-bad domains

### Phase 3 — Deep Dive & Correlation

9. **Pivot on discoveries**: When you find a suspicious indicator, pivot on it:
   - Found a suspicious IP → search all indices for that IP across all field names
   - Found a suspicious process → trace its parent chain, child processes, network connections, and file operations
   - Found a suspicious file → search for its hash, name, and creation events across hosts
   - Found a compromised user → trace all their logon events, process launches, and accessed resources
10. **Build a timeline**: Order events chronologically to reconstruct the attack sequence. Identify:
    - Initial access vector (phishing, exploitation, valid credentials)
    - Execution methods
    - Persistence mechanisms
    - Lateral movement paths
    - Data staging and exfiltration indicators
    - Command & control communication

### Phase 4 — Binary Analysis (if applicable)

If suspicious binaries or malware samples are available in Ghidra:

11. **Triage the binary**:
    - `mcp_ghidra_list_imports` — Identify suspicious API calls (network, process injection, crypto, anti-debug)
    - `mcp_ghidra_list_exports` — Check exported functions
    - `mcp_ghidra_list_strings` — Extract hardcoded IPs, URLs, domains, registry keys, file paths, credentials, C2 configs
    - `mcp_ghidra_list_segments` — Check for packed/encrypted sections (high entropy, unusual section names)
12. **Analyze key functions**:
    - `mcp_ghidra_decompile_function` on `main`, `WinMain`, `DllMain`, or entry points
    - Decompile functions that reference suspicious imports (e.g., `CreateRemoteThread`, `VirtualAllocEx`, `InternetOpenA`, `URLDownloadToFile`)
    - Use `mcp_ghidra_get_function_xrefs` to trace call chains from interesting functions
13. **Extract IOCs from the binary**: Hardcoded C2 addresses, encryption keys, mutex names, user-agent strings, file drop paths

### Phase 5 — Report Generation

14. **Compile the incident report** with the following structure:

#### Report Structure

**Executive Summary**
- One-paragraph description of what happened, when, and the impact

**IOC Table**
Present ALL identified indicators in a table:

| IOC Type | Value | Context / Where Found | Evidence |
|----------|-------|-----------------------|----------|
| IP Address | x.x.x.x | C2 communication | ES query showing connection events |
| Domain | evil.example | DNS resolution | ES query showing DNS lookups |
| File Hash | sha256:... | Dropped malware | ES file creation event / Ghidra analysis |
| File Path | C:\Temp\payload.exe | Malware location | ES process execution log |
| User Account | compromised_user | Lateral movement | ES authentication events |
| Registry Key | HKCU\...\Run\... | Persistence | ES registry modification event |

**Attack Timeline**
Chronological sequence of events with timestamps and evidence references.

**Interesting Findings**
Noteworthy attacker behaviors, techniques, mistakes, or unusual patterns — things that reveal tradecraft, intent, or sophistication level.

**What Likely Happened**
Narrative reconstruction connecting all evidence into a coherent attack story, mapping to MITRE ATT&CK tactics where possible (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Command & Control, Impact).

## Query Guidelines

- Start broad and narrow down. Don't assume field names — check mappings first.
- Use `LIMIT` sensibly in ES|QL: start with small result sets (50-100), expand if needed.
- When searching for IOCs across all indices, query each relevant index separately.
- Filter by time ranges when known to reduce noise.
- Use wildcard patterns for partial matches on file paths and command lines.
- If a query returns no results, try alternative field names (check mappings) or broaden the search terms.

## Evidence Standard

Every claimed IOC or finding MUST include:
- The specific query or tool call that produced the evidence
- The raw data supporting the conclusion
- Context explaining why it is suspicious or malicious

Do not speculate without evidence. Clearly distinguish between confirmed indicators and hypotheses.
