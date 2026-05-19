# Ludus

## Kjør config

Start `ludus-config.yml` etter forklaring i Ludus docs.

## DNS

http://10.3.10.254:3000/#dns_rewrites
`admin:password`

| Domain | IP Address |
|--------|------------|
| f1leshare.net | 10.3.124.26 |
| MiccosoftUpdate.com | 10.3.97.182 |
| windowsupdater.tk | 10.3.215.83 |



# Elasticsearch

## Agenter

- Elastic Defend
  - Slå av alle detections
  - Sett som "official Antivirus solution for Windows OS"
- Windows
- System
- Network Packet Capture
  - Legg til "Include body for"
    - `text/html`
    - `text/plain`
    - `application/json`
    - `application/octet-stream`


## Reset

Bruk denne i Dev Tools. VIKTIG! Kl. 14:00 i koden tilsvarer klokka 15:00 i virkeligheten!

```
POST /*/_delete_by_query?wait_for_completion=false&conflicts=proceed&slices=auto
{
  "query": {
    "bool": {
      "should": [
        { "range": { "@timestamp": { "lt": "2026-03-25T12:00:00Z" } } },
        { "range": { "@timestamp": { "gt": "2026-03-26T12:00:00Z" } } }
      ]
    }
  }
}

GET _tasks/<task_id>
```

```bash
ludus snapshots revert clean-install
```


## Deployer angripers servere

### Kopier filer

```bash
scp -r downloadserver/ debian@10.3.124.26:/home/debian/
scp -r loggingserver/  debian@10.3.97.182:/home/debian/
scp -r c2server/       debian@10.3.215.83:/home/debian/
```

### Deployer servere

```bash
sudo apt update
sudo apt install python3-pip -y
sudo -H python3 -m pip install -r requirements.txt --break-system-packages
sudo python3 app.py
```

### Forberedelser på maskiner

- Plasser .eml fil på skrivebordet

  `polen.eml`

  ```
  Return-Path: <emil.andersson@kongsberg.com>
  Received: from mail.kongsberg.com (mail.kongsberg.com [192.0.2.1])
      by mail.kongsberg.com (8.14.7/8.14.7) with ESMTP id m3L5GdH3001234
      for <anders@kongsberg.com>; Thu, 26 Mar 2026 10:15:00 +0100
  From: Emil Andersson <emil.andersson@kongsberg.com>
  To: Anders <anders@kongsberg.com>
  Subject: Polen NASAMS-avtale
  Date: Thu, 26 Mar 2026 10:15:00 +0100
  MIME-Version: 1.0
  Content-Type: text/plain; charset="UTF-8"
  Content-Transfer-Encoding: 7bit

  Hei Anders,

  Ville bare gi deg en kort oppdatering. Vi har fått bekreftet at de polske vennene våre har valgt å kjøpe NASAMS fra Kongsberg. Avtalen skal være på rundt 3,5–4 milliarder kroner, og systemet inkluderer både radar, kommandoplass og lanseringsenheter med langtrekkende presisjonsraketter.

  NASAMS gir betydelig fleksibilitet med integrasjon mot ulike luftvernsystemer, rask respons på mål i alle høyder og mulighet for samtidig håndtering av flere trusler. Den valgte pakken innebærer full logistikk- og vedlikeholdsoppfølging, så kunden får et komplett, operativt luftvernsystem.

  Det innebærer at vi må ansette 40–50 personer i Polen. Har du noen tanker om hvordan vi kan rekruttere fortest mulig? Vi må få på plass et team rimelig kvikt.

  Noter deg at informasjonen ikke er offentlig kjent, så vær nøye med hvem du deler dette med.

  Med vennlig hilsen,
  Emil Andersson
  Kongsberg Gruppen
  ```

- Slå av bgtask i taskmanager på alle klienter.
- Sett språk til russisk på Johns maskin.



# Angrep

## Gjennomføring

### Anders maskin

Finner denne på nordnet:

http://f1leshare.net/?file=kongsberggrupper-insider&share=nordnet.no


Etter angrepet logger brukeren seg inn på https://vaultwarden.ryo.no:

anders@kongsberg.com
Anders
anderserkul123

Kopierer SSH private key til utklippstavle

```ps1
dir "C:\Users"
dir "C:\Users\anders\Documents"
dir "C:\Users\anders\Desktop"
type "C:\Users\anders\Desktop\polen.eml"
```


### John maskin

Finner denne på reddit:

Norway buying new jets?

http://f1leshare.net/?file=norway-buys-80-jets&share=reddit.com
