---
name: incident-analysis
description: "Perform a structured incident analysis using Elasticsearch and Ghidra MCP tools.
---

# Incident Analysis

Create a report based of the evidence from both available tools. Everything has to be supported by concrete evidence.

You have access to these tools:
- Ghidra with the payload of the attacker. Use it for malware reverse engineering to understand what the malware can do.
- Elasticsearch with host logs of what actually happened
- Python code runner to solve cryptographic problems

Search for suspicious activity across both tools. For every finding, immediately cross-check the other tool. Document every finding with concrete evidence from both tools before moving on.

Use restrictions in the searches to only include interesting fields to avoid information overload.

When exfiltration is identified, recover the raw content of what was stolen.

Check also what happened immediately before and after the attack to fill the entire timeline.

## Write Report (`incident-report.md`)

I want a detailed report that contains a timeline summary and detailed IOC analysis. The timeline summary should cover:

- **Motivation** 
- **Attack vector** 
- **Impact** - what value was compromised and exfiltrated

Create a list providing all relevant IOC details.
