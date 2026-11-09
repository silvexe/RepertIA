# RepertIA tested on two documented smartphones: Android 14 and iOS 17

*RepertIA 3.0.2 — November 2026 · Italiano: [smartphone-hickman.it.md](smartphone-hickman.it.md) · Other tests: [index](README.md)*

## In short

We analysed with RepertIA the public images of two phones prepared by **Joshua Hickman** for the forensic community:

- a **Google Pixel 7a with Android 14**;
- an **iPhone 11 with iOS 17.3**.

Hickman used the phones like anyone would and wrote down **every action with date and time**: messages sent and
received, calls, websites visited, Wi-Fi networks, Bluetooth devices. He published these notes together with the
images. Each extraction also comes with the acquisition summary, with the SHA-256 hash and the phone's details.

We checked **264 documented actions** one by one.

- **RepertIA finds all 262 actions present in the phones' data.**
- **In 257 cases** text, direction (sent or received) and time match the document.
- **In 5 cases the document has a detail wrong,** and RepertIA reports the right one, checked on the original
  databases. Two directions are reversed: the same reply is noted as "sent" by both sides. One time is noted ten minutes
  early, and two calls have the phone's own number.
- **2 calls noted in the document are not in the phone's call log:** no tool can find them.
- **Agreement between the two phones.** Hickman made the two phones talk to each other on WhatsApp, Signal and
  Telegram. Of 47 messages present on both, RepertIA gives on the Pixel and on the iPhone **the same time, at most one
  second apart**.
- **Phone identity:** the SHA-256 hash matches the attached summary, and so do version, patch and build. On Android the
  list of installed apps also matches app by app (369 of 369).
- **No invented results.** The messages that Hickman deleted and that no longer exist in the phone's files (checked byte
  by byte) are not presented as recovered.
- **A limit found and fixed with this test:** an iMessage deleted less than 30 days earlier stays in "Recently Deleted".
  RepertIA showed its text without saying it had been deleted. From 3.0.2 it flags it as "deleted by the user", with
  the date of deletion (see below).

## The reference sources

All references come from the documents distributed **together with the images**. Anyone who downloads the images has
them:

| Phone | Creation documentation (Hickman) | Acquisition summary attached to the extraction |
|---|---|---|
| Pixel 7a, Android 14 | `Android14-ImageCreation.pdf` | `EXTRACTION_FFS.ufd`, `SummaryReport.pdf`, `InstalledAppsList.txt` |
| iPhone 11, iOS 17.3 | `iOS17-ImageCreation.pdf` | `EXTRACTION_FFS.ufd`, `SummaryReport.pdf` |

The document's times are local: US East Coast, with daylight saving time, and with a week in Europe for the iPhone, as
stated in the document itself. We converted them to UTC.

## How we checked

- **A new case for each phone**, created with RepertIA 3.0.2 from the extraction zip, with SHA-256 and artefact
  analysis enabled (ALEAPP 2026.4.5 on Android, iLEAPP on iOS).
- **Comparison with a script.** Every action was searched by a script, with no manual choices. The message must have the
  same direction and a fragment of the document's text, within two minutes of the noted time. The document's times are
  handwritten and to the minute.
- **Check at the source.** When an action is not found, the phone's original database, extracted from the same zip, is
  opened to see whether the data is really there.

## Results

| What is checked | Android: actions | **Android: found** | iOS: actions | **iOS: found** |
|---|---|---|---|---|
| Messages (RCS/SMS/MMS, iMessage) | 17 | **17** | 22 | **22** |
| WhatsApp: messages | 18 | **18** | 35 | **34** ¹ |
| WhatsApp: audio and video calls | 4 | **4** | 8 | **8** |
| Signal: messages | 16 | **16** | 35 | **34** ² |
| Telegram: messages | 19 | **18** ³ | 37 | **37** |
| Calls (Phone app) | 5 | **3** ⁴ | 6 | **4** ⁵ |
| Browsing (Chrome, Safari) | 7 | **7** | 4 | **4** ⁶ |
| Wi-Fi networks | 10 | **10** | 14 | **14** |
| Paired Bluetooth devices | 4 | **4** | 3 | **3** ⁷ |
| **Total** | **100** | **97** | **164** | **160** |

On iOS, in addition, **messages edited** after sending (4 of 4) appear with their final text. On both phones the tabs in
**private browsing** and incognito correctly leave no trace in the history.

*Notes on the actions not found (the checks are in the next section):*
1. WhatsApp iOS, 30/01 at 15:11: direction reversed in the document.
2. Signal iOS, 28/07/2023: time noted as 12:13 instead of 12:23.
3. Telegram Android, 31/01 at 12:15: direction reversed in the document.
4. Android calls of 1 February and 4 June: not in the phone's call log.
5. iOS calls of 27 July: the document gives the iPhone's own number.
6. Safari: compared on the time, because the history had been cleared (see below).
7. Fitbit: compared on the name, because iOS does not record the MAC address of Bluetooth LE devices.

| Phone identity | Android: reference | **RepertIA** | iOS: reference | **RepertIA** |
|---|---|---|---|---|
| SHA-256 of the zip | `a9a2d881…0a8464a` | **same** | `7e603d01…b9014fa` | **same** |
| Version | Android 14 | **14** | iOS 17.3 | **17.3** |
| Build | UQ1A.240105.004 | **same** | 21D50 | **same** |
| Patch | 2024-01-05 | **2024-01-05** | — | — |
| Installed apps | 369 | **369, same list** | not given | — |
| IMEI | given | not shown | not given | — |

## The actions not found, checked at the source

- **The direction of two messages.** The Android document marks as sent the "I'll send a picture" of 12:15 on Telegram.
  The iOS document marks the same message as sent from the iPhone, and in the Telegram database the sender is the
  iPhone. The same happens for "It's gone" on WhatsApp at 15:11: for the Pixel it is sent, for the iPhone it is
  received. In both cases RepertIA reports the direction recorded by the app.
- **A wrong time.** On Signal, in the iOS document, "Got it. I'll audio call you in a minute" is noted at 12:13, among
  actions of 12:22 and 12:24. In the database it is from 12:23.
- **Android calls of 1 February and 4 June.** They are not in the phone's call log (`calllog.db`, 2655 entries). For the
  first number there is only a call of 29 January, which RepertIA shows.
- **iOS calls of 27 July.** The document gives the iPhone's own number. The log has the Pixel's number, and according to
  the Android document the Pixel calls the iPhone at 17:40. RepertIA shows the two calls with the right time and
  direction.

## Deleted messages

On each phone Hickman deleted some messages, in Messages, WhatsApp, Signal and Telegram. We applied RepertIA's recovery
of deleted records, the one behind the "Deleted records" button, to the original databases. Then we searched for the
texts **byte by byte** in all the database files, WAL files included, also tolerating double spaces.

- **Texts gone** (Android: Messages, WhatsApp and Telegram; iOS: three Messages messages and one WhatsApp message). They
  are no longer in any file: no tool could recover them from these extractions. **RepertIA does not invent them.**
- **An iMessage in "Recently Deleted"** (iOS, 28 July, 11:07). iOS keeps deleted messages for 30 days, and this one had
  been deleted shortly before the acquisition. With this test we saw that RepertIA showed its text in the right
  conversation, but **without flagging it as deleted**. We fixed it. The message now appears as **"deleted by the user on
  28/07/2024 at 11:08"**, in the chat view, in the deleted filter and in the report. The time is the one Hickman notes for
  the deletion, read from the `chat_recoverable_message_join` table of `sms.db`.
- **Signal and Telegram on iOS:** the databases of these two apps are encrypted, so the byte-by-byte check is not
  possible.

## Other observations

- **Safari (iOS).** The Safari history no longer contains the documented visits: `History.db` has a single visit, from
  28 July. RepertIA does show, from the iOS Biome artefacts, the **deleted** Safari history entries, at the same times as
  the documented visits (18:13, 18:15, 19:37, 19:38). The comparison is therefore on the time; the address is no longer
  in the data.
- **iLEAPP rows.** On this iPhone iLEAPP produces over 21 million rows. RepertIA imports at most 2 million, and says so in
  the log. We checked row by row that **all artefacts are imported in full**, except FSEvents, the low-level logs of
  file system changes. These remain available in full in the iLEAPP report attached to the case.

## Small differences in the documents

The documents are handwritten and in some places summarise or are slightly off. We mention them for whoever wants to
repeat the test.

- **Summarised texts:** the document writes "a document", "I deleted it", "Hopefully, that continues". The phones have
  "the document", "I deleted.", "Hopefully that continues".
- **Wi-Fi network names:** the documents have "DNCR-Acquarium_Visitor", "MarriotBonvoy", "MyWay Guest". The saved
  networks are "DNCR-Aquarium_Visitor", "MarriottBonvoy", "My Way Tavern Guest".
- **Directions, times and numbers** given above.

## Limits

- **Coverage:** we checked the apps most used in investigations (messaging, calls, browsing, networks, Bluetooth). The
  documents describe more than 50 apps per phone: the others remain to be checked in a later test.
- **Pixel IMEI:** RepertIA does not show it, and the number does not appear in the data read from the extraction. The
  acquisition summary read it from the powered-on phone.
- **Time tolerance:** two minutes. Of the 230 actions found with a time (83 Android, 147 iOS), 224 fall within the noted
  minute. The other six are less than a minute and a half off:
  - two iOS calls started just before the noted minute;
  - a Telegram message;
  - two Safari Biome traces;
  - mlb.com on Chrome. Here the history keeps the last visit (21:16, when Hickman went back to the page), not the first
    one at 21:14.

## How to repeat the test

1. Download the "Android 14" and "iOS 17" images from Joshua Hickman's site (thebinaryhick.blog), with the attached
   documents.
2. In RepertIA: **New analysis → Smartphone**, choose `EXTRACTION_FFS.zip`, with SHA-256 and ALEAPP/iLEAPP.
3. Run the comparison scripts in [tools/prove](../../tools/prove/README.md), all read-only:
   - `hickman_riferimenti_android14.py` and `hickman_riferimenti_ios17.py`: the references taken from the documents;
   - `hickman_confronto.py <case> <references> <app list or -> <output>`: the comparison;
   - `hickman_cancellati.py`: recovery of deleted records on the original databases.

   In the scripts phone numbers are reduced to their last 4 digits and Bluetooth addresses to their last 3 bytes, so as
   not to republish identifiers.

## Sources

- Joshua Hickman, *Android 14 Image* and *iOS 17 Image*, with `Android14-ImageCreation.pdf` and `iOS17-ImageCreation.pdf`:
  https://thebinaryhick.blog
- Acquisition summaries attached to the extractions: `EXTRACTION_FFS.ufd`, `SummaryReport.pdf`,
  `InstalledAppsList.txt`.

*Reports and questions: [repository issues](https://github.com/silvexe/RepertIA/issues).*
