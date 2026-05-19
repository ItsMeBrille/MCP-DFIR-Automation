# Tester

- `_assets` inneholder mcp-serverfilene.

## Innhold i testmappene

- `.vscode/mcp.json` for ¨å koble til MCP-serverne i `_assets`.
- `.github/skills/` inneholder skils.
- `.github/agents/` inneholder instruksjoner for agenter.
- `README.md` inneholder en forklaring av hvordan hver test kan reproduseres, og eventuelle bemerkninger for vår gjennomgang av testene.
- `Answers.md` inneholder svaret vi fikk fra agenter, limt inn i sin helhet.
- `incident-report.md` er en rapport agentene selv har generert.

## Hvordan kjøre testene

Installer MCP-serverene og oppdater `_assets/elastic/.env` med en apinøkkel for Elastic Search.

Hopp inn i mappen og vscode vil automatisk koble til mcp-serverene. i noen tilfeller må serverne startes manuelt.
