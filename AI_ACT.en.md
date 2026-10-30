# RepertIA and the EU Artificial Intelligence Act (AI Act)

*Italiano: [AI_ACT.md](AI_ACT.md).*

> **This is not legal advice.** This document describes how RepertIA is built and the author's assessment under
> Regulation (EU) 2024/1689 ("AI Act"). Whoever adopts the tool must make their own assessment, with their data
> protection officer and legal office, and check any later amendments to the Regulation and to national law.

Program version it refers to: **2.20.3**.

## 1. What RepertIA does and where AI is involved

RepertIA is a tool for the forensic analysis of forensic images (disks, USB sticks, memory cards) and smartphone
extractions. Almost all of its work **does not use artificial intelligence**: file listing including deleted files,
timeline, hashes, carving, system artifacts, chats, searches and reports are produced by deterministic tools (The Sleuth
Kit, plaso, PhotoRec, bulk_extractor, iLEAPP/ALEAPP, RepertIA's own readers) and are traced in the hash-chained log
(`audit_log.jsonl`).

AI is involved in three places, all **optional**:

| Function | Component | Where it runs |
|---|---|---|
| Natural-language questions to the agent, which consults the case data with read-only tools and may propose "findings" | language model chosen by the analyst (LM Studio, llama-server, Ollama) | on the analyst's computer or on a server the analyst indicates |
| Automatic transcription of audio | Whisper (whisper.cpp), model downloaded only with the analyst's consent | on the analyst's computer, offline |
| Text in images (OCR) | Tesseract (optical character recognition) | on the analyst's computer |

No language model is included in the packages. Without a model all analyses, searches and reports work.

## 2. Intended purpose

RepertIA is intended to **support the forensic analyst**:

- in searching, indexing and consulting the data of a forensic image or extraction;
- as a **preparatory task**: the agent helps find elements and formulate hypotheses, which the analyst checks on the
  forensic tools and on the original data.

**Conclusions remain with the analyst.** Every answer of the agent is marked as a "hint to be checked" and every
finding proposed by the agent stays "to be checked" until the analyst confirms it (operator and date in the case and in
the log).

## 3. Excluded uses

RepertIA is **not designed or intended** to:

- **evaluate the reliability of evidence** in the course of criminal investigations or proceedings;
- **profile natural persons** or assess their risk, personality, behaviour or likelihood of committing offences;
- **take automated decisions** or replace the assessment of the analyst, the prosecutor or the judge;
- perform **biometric recognition** (faces, voices, fingerprints) or biometric categorisation of persons;
- interpret the law or apply it to the facts.

Using it for these purposes is outside its intended purpose: whoever does so is responsible for it and, under the
Regulation, may become the "provider" of a high-risk system (see point 6).

## 4. Risk assessment (Article 6(3))

Annex III of the Regulation lists the areas in which an AI system may be high-risk. Those close to the use of RepertIA
are:

- **point 6 (law enforcement)**, in particular (c): systems intended to be used by or on behalf of law enforcement
  authorities **to evaluate the reliability of evidence** in the course of the investigation or prosecution of criminal
  offences; and (e): **profiling** of natural persons in the course of the detection, investigation or prosecution of
  criminal offences;
- **point 8 (administration of justice)**, (a): systems intended to assist a judicial authority in **researching and
  interpreting facts and the law** and in applying the law to a concrete set of facts.

Article 6(3) provides that an Annex III system **shall not be considered high-risk** where it does not pose a
significant risk of harm to health, safety or fundamental rights, including by not materially influencing the outcome of
decision-making; this applies, among others, where the system performs a **narrow procedural task** (point (a)) or a
**preparatory task** to an assessment relevant for the purposes of Annex III (point (d)). The derogation **never
applies** if the system performs profiling of natural persons.

The author's assessment:

- RepertIA **does not evaluate the reliability of evidence**: it extracts, indexes and shows the data with a verifiable
  reference (offset, inode, path, database, table, row, hash); the assessment remains with the analyst;
- the agent performs a **preparatory task** (search, summary, hypotheses) and its result does not enter the report as
  verified without the analyst's explicit confirmation;
- it **does not profile** and does not score persons;
- transcription and OCR are **narrow procedural tasks** (turning audio and images into searchable text), always marked
  as automatic and to be checked.

For these reasons the author considers that RepertIA, **used according to its intended purpose**, falls under
Article 6(3) and is not a high-risk system.

Notes:

- Article 6(4) requires a provider relying on the derogation to **document the assessment** before placing on the
  market or putting into service (this document is part of it) and to provide it to the authorities on request;
  Article 49(2) also provides for **registration in the EU database** of Annex III systems considered not high-risk;
- RepertIA is distributed under a **free licence** (GPL-3.0-or-later): Article 2(12) excludes from the Regulation AI
  systems released under free and open-source licences, **unless** they are placed on the market or put into service as
  high-risk systems or fall under Article 5 or 50. The transparency obligations of Article 50 are therefore met (point
  5); adopters should nevertheless assess with their legal office how these provisions apply to their case.

## 5. Transparency obligations (Article 50) and how they are met

| Obligation | How RepertIA meets it |
|---|---|
| **Art. 50(1)** – persons interacting with an AI system must be informed | Under **every answer** of the agent there is the fixed label "Answer generated by an AI model (*model name*): hint to be checked" (also on the command line). The LLM server box shows the model, server and context in use. |
| **Art. 50(2)** – AI-generated text must be recognisable as such, also in a machine-readable format | **Agent findings**: in `findings.json` every finding has `"origine": "modello IA"` (AI model), the model name, the server and `"stato": "da verificare"` (to be checked); in the reports (Markdown, Word, PDF, portable report) every finding carries the label "Generated by AI model (*name*) – to be checked" or "Verified by *operator* on *date*"; the sentence "Every finding was verified by the analyst" appears **only** if all findings have been confirmed, otherwise the report states how many are verified and how many are not; the **metadata** of the Word and PDF files state that the document contains AI-generated text (description/subject and the keyword "AI-generated content"). **Transcriptions** and **OCR**: always marked as "automatic transcription" and "automatic OCR text" in the interface and in the reports. |
| **External LLM server** (confidentiality, not an Art. 50 obligation) | If the server address is neither on this computer nor on the local network (private IPs 10.x, 172.16–31.x, 192.168.x, local names), RepertIA shows an **explicit warning before using it**, records it in the case and in the log, and the report says "external server indicated by the analyst: *address*" instead of "internal network". |

Confirming a finding ("I confirm, verified") records operator and date in `findings.json` and in the hash-chained log
`audit_log.jsonl` (entry `finding_verificato`). The automated acceptance test checks that a finding created by the
agent is "to be checked" in the report and verified after the confirmation.

## 6. Note for the offices adopting it

- Whoever uses RepertIA under their own authority in the course of their professional activity is a **"deployer"**
  under Article 3. They must assess its use in their own context, ensure adequate **AI literacy** of their staff
  (Article 4) and effective **human oversight**: the findings proposed by the agent must be checked on the forensic tools
  before entering a report.
- In Italy, **Law no. 132 of 23 September 2025** (provisions on artificial intelligence) reaffirms that in public
  administration and in judicial activity AI is a **support** and that decisions and the assessment of facts and
  evidence remain with the responsible person. Offices should assess their internal rules accordingly.
- **Impact assessment**: forensic images usually contain personal data, including special categories. Assess the need
  for a data protection impact assessment (Article 35 GDPR or, for police and judicial authorities, the national law
  implementing Directive (EU) 2016/680, in Italy Legislative Decree 51/2018) and, if the tool were used for high-risk
  purposes, the fundamental rights impact assessment of Article 27.
- **LLM server**: prefer a model on the analyst's computer or on an internal network server. An external server sends
  questions and the content read by the agent outside the network: it must be authorised case by case.
- **When you become a "provider" (Article 25)**: whoever **substantially modifies** RepertIA, distributes it under
  **their own name or trademark**, or uses or adapts it for a **high-risk purpose** (for example evaluating the
  reliability of evidence or profiling persons) may take on the obligations of the provider of a high-risk system.

## 7. References

- Regulation (EU) 2024/1689 of the European Parliament and of the Council of 13 June 2024 (AI Act): Article 2(12);
  Article 3; Article 4; Article 6(3) and (4); Article 25; Article 27; Article 49(2); Article 50; Annex III, points 6 and
  8.
- Italian Law no. 132 of 23 September 2025, provisions and delegations to the Government on artificial intelligence.
- Regulation (EU) 2016/679 (GDPR), Article 35; Directive (EU) 2016/680 and Italian Legislative Decree no. 51 of 18 May
  2018.
- RepertIA documentation: [README](README.md), [manual](docs/MANUAL.md), [validation](VALIDATION.md),
  [change log](CHANGELOG.en.md).
