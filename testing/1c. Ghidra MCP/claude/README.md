Dette er baseline test for kun Ghidra uten elastic, fjerner dermed noen mention av elastic.


```
You have access to Ghidra MCP.

Perform incident analysis to identify IOCs and artifacts. Provide proof for each indicator from available data/tools. Include interesting details that reveal what the attacker did, and explain what likely happened.
```
### Steg å gjøre før kjøring:

1. Starte alle nødvendige mcp servere (Ghidra, Elastic, Pylance)
2. Om nødvendig resette Ghidra
3. Åpne copilot debugger
```
>github.copilot.chat.agentdebug
```
4. Dobbelsjekke at riktig agent kjører

### Etter kjøring
1. Om ingen egen .md fil er lagd, kopier svaret inn i en Answer.md
2. Lagre debug output som json, deretter flytt inn i riktig folder som logs.json

