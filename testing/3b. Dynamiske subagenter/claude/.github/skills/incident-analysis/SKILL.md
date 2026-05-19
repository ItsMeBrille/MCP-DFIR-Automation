---
name: incident-analysis
description: Perform security incident analysis using Elasticsearch and Ghidra MCP tools.
---

# Incident Analysis

Systematic incident investigation combining Elasticsearch (log/event analysis) and Ghidra (binary/malware reverse engineering). The goal is an evidence-backed incident report with confirmed IOCs and a full reconstruction of what happened and what the attackers did. 

Key principle: Ghidra reveals what the binary can do. Elasticsearch reveals what it did do. Always cross-reference both:

## Elasticsearch

- Discover indices, retrieve mappings, determine time ranges and available entities.
- Search all relevant indices for IOCs and suspicious activity using **MITRE ATT&CK** as a guide. Pivot on every lead - when you find something suspicious, follow associated entities. Use both **ES|QL** and **Query DSL**. Adapt the examples below to the actual indices and fields you discover.


## Ghidra

Always include decompiled code or raw Ghidra output. No claims without proof.

- List functions, extract strings, enumerate imports. Get a high-level picture of what the binary is and what it can do.
- Decompile and analyze functions. Classify capabilities using **MITRE ATT&CK**. For every capability, include the decompiled code as evidence. Trace cross-references and data flows until the picture is complete.
- Compile all concrete IOCs: network indicators, file paths, keys, identifiers, or any artifact useful for detection or hunting.


## Working State Management

- Use the todo list to track every phase and sub-task. Mark each in-progress or completed as you go.
- After completing each phase, write a summary to session memory with: findings so far, open questions, and next steps.
- Before starting a new phase, re-read the previous phase summary to maintain full context.
- Use both MCP toolsets directly. Do not just summarize but call the tools yourself and work with the raw results.

---

## Procedure

### Phase 1 - Reconnaissance & Scoping
- Map available Elasticsearch data
- Survey the binary in Ghidra

### Step 2 - Cross-Correlation

Read both findings files. For every finding, check the other tool directly:

- **Ghidra → Elasticsearch:** Search for evidence each capability was actually executed.
- **Elasticsearch → Ghidra:** Find the code responsible for suspicious telemetry.

Use BOTH MCP toolsets directly - do not just summarize.

### Step 3 - Deep Dive

For every critical IOC:
1. **Expand timeline** - search Elasticsearch for events before/after the IOC.
2. **Validate in Ghidra** - confirm code supports observed behavior.
3. **Exhaust all angles** - every capability (Ghidra) and every action (Elasticsearch) documented.

When exfiltration is identified, recover the raw content of what was stolen.

### Step 4 - Gap Resolution

Resolve both specialists' **Gaps** sections using the opposite toolset.

### Step 5 - Write Report (`incident-report.md`)

#### 1. Timeline Summary
- **Motivation**
- **Attack vector**
- **Impact** - what was compromised/exfiltrated, including actual raw content of stolen data.

#### 2. IOC Details
One subsection per IOC:
1. **Description** - what it is and why it matters
2. **Evidence query** - the Elasticsearch query or Ghidra tool call
3. **Raw data** - actual returned data
4. **Context** - why it is suspicious or malicious

Do NOT speculate without evidence. Label everything **confirmed** or **hypothesis**.
