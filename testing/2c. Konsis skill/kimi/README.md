# Test 2 KI generert skill
Dette er en test for å se om en KI generert skill vil jobbe bedre en uten en KI generert skill. For å gjære det enklere vil det bli laget kun en skill fil, i henhold til prosedyren vist under:


## Prompt for gjennomføring 
```
Perform incident analysis to identify IOCs and artifacts. Provide proof for each indicator from available data/tools. Include interesting details that reveal what the attacker did, and explain what likely happened.
```
Det vil brukes ```/incident-analysis``` for å tvinge fram bruk av skills.


### Steg å gjøre før kjøring:

1. Starte alle nødvendige mcp servere (Ghidra, Elastic, Pylance)
2. Om nødvendig resette Ghidra
3. Åpne copilot debugger
```
>github.copilot.chat.agentdebug
```
4. Dobbelsjekke at riktig agent kjører

## Notat
Denne prøvde faktisk å dekryptere med pylance men kalrte ikke helt.