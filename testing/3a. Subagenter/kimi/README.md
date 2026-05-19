# Test 2 KI generert multiagent
Her Brukes en detaljert skill men med allerede inkluderte esql og dsl eksempler (laget av KI), bygget oppå en menneskelagd skill. 

Jeg skal undersøke om eskemplemene må endres for å forbedre resultat.

## Prompt for gjennomføring 
```
You have access to Elasticsearch MCP and Ghidra MCP.

Perform incident analysis to identify IOCs and artifacts. Provide proof for each indicator from available data/tools. Include interesting details that reveal what the attacker did, and explain what likely happened.
```
Det vil brukes ```/incident-analysis``` for å tvinge fram bruk av skills.
```

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
