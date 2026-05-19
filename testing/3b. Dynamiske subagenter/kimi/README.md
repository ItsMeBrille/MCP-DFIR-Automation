# Test 2 KI naturlig multiagenter

Tanken her er å bruke skill fra forrigie testing, men la agenten naturlig spawne sin egne sub-agenter. Med egen handoff.


## Prompt for gjennomføring 
```
You have access to Elasticsearch MCP and Ghidra MCP.

Perform incident analysis to identify IOCs and artifacts. Provide proof for each indicator from available data/tools. Include interesting details that reveal what the attacker did, and explain what likely happened.
```
Det vil brukes ```/incident-analysis``` for å tvinge fram bruk av skills. Samt nevne at agenten skal spawne subagenter. 

```
Perform incident analysis to identify IOCs and artifacts. Provide proof for each indicator from available data/tools. Include interesting details that reveal what the attacker did, and explain what likely happened.

Delegate work by spawning sub-agents. 
```


### Steg å gjøre før kjøring:

1. Starte alle nødvendige mcp servere (Ghidra, Elastic, Pylance)
2. Om nødvendig resette Ghidra
3. Åpne copilot debugger
```
>github.copilot.chat.agentdebug
```
4. Dobbelsjekke at riktig agent kjører
