# RepertIA tested on a full case: NIST "Data Leakage"

*RepertIA 3.0.2 — November 2026 · Italiano: [nist-data-leakage.it.md](nist-data-leakage.it.md) · Other tests: [index](README.md)*

## In short

**NIST** prepared a full, public test case, the **"Data Leakage Case"**. An employee takes confidential documents out
of the company, using a USB stick, a CD-R, a cloud service and e-mail, and then tries to erase the traces. The case
contains the images of the employee's **Windows 7 PC**, of **two USB sticks** and of a **CD-R**, together with **60
questions with NIST's official answers**.

We opened the images with RepertIA and compared the results with the answers, question by question.

- **53 questions can be checked on the images, and RepertIA's answers are NIST's.** There is one limit: an e-mail left
  in the unused space of the Outlook archive, which RepertIA does not read yet.
- **In some points it is the NIST answer that is inaccurate,** and we checked it on the data: an event with the wrong
  number, two swapped dates, a file name that does not exist in Windows 7, two tables one hour off.
- **The other 7 questions are analyst reasoning** (why, how, the overall timeline). RepertIA provides the facts to reason
  on, but the conclusion is the analyst's.
- **The test revealed seven defects or gaps in RepertIA, all fixed in 3.0.2.**
- An automatic script repeats **56 checks** on the cases prepared by RepertIA: **56 of 56 passed**.

## The case

| Media | What it contains | How it was opened with RepertIA |
|---|---|---|
| PC | Windows 7 Ultimate, one user, Outlook, Chrome and Internet Explorer, Google Drive, shadow copies | E01 image, with extended analyses and shadow copies |
| USB stick RM#2 | Files copied and then deleted with a quick format | E01 image, with extended analyses |
| CD-R RM#3 | Burned several times: the files written earlier remain in the previous sessions | Logical source |

The images can be downloaded from the NIST CFReDS site. The SHA-1 hashes of the copies used match those published by
NIST.

## How we checked

- **One case per media**, prepared with RepertIA 3.0.2.
- **Times in UTC.** The NIST answers give New York times, which we converted to UTC. In March 2015 New York was already
  on daylight saving time (UTC-4).
- **Comparison with a script**, which reads the cases read-only and compares them with the values of the NIST answers.
- **Check at the source.** Where RepertIA and NIST disagreed, we reread the raw data to find out who was right.

## Results

| Topic | Questions | Outcome |
|---|---|---|
| Images, partitions, system | 1-5 | Hashes, partitions, Windows version, time zone and computer name same as NIST |
| Accounts and last user | 6-7 | Same; on one account RepertIA also finds a failed logon attempt that NIST does not list |
| Shutdown, network, programs, executions | 8-12 | Same, including the 14 executions with their times |
| Browsing and searches | 13-17 | Chrome and Internet Explorer 11; the words searched in Chrome, in Bing and in File Explorer |
| E-mail | 18-21 | Program, archive and account same. Of the messages, 10 are read with NIST's sending time, while the one in the unused space of the archive is not read |
| USB sticks | 22 | The two devices, with serial numbers and times |
| Renames and opened folders | 23-28 | 9 renames with the right old name; folders and files opened from the stick and the network drive |
| Cloud services | 29-31 | Google Drive, the deleted files and the account |
| Burning and CD-R | 32-35 | The burn folder, the event, the 17 files in the previous sessions of the CD-R, the files opened from the CD |
| Documents and printing | 36-37 | Dates of the resignation letter, printing to an XPS file |
| Thumbnails, notes, Windows Search | 38-46 | Same |
| Shadow copies and Recycle Bin | 47-51 | Same (50 is reasoning) |
| Anti-forensics and USB stick | 52-55 | The 17 deleted files recovered from the stick; 15 with the false extension flagged, the other 2 consistent with their content |
| CD-R and conclusions | 56-60 | The files hidden on the CD-R and the burning time checked; the rest is reasoning |

**Total: 53 questions checked on the images, 7 reasoning questions.**

## Where the NIST answer is inaccurate

We point them out so that whoever repeats the test does not mistake these differences for tool errors.

- **Accounts and installed programs (questions 6 and 10): one hour off.** The times of these two tables match standard
  time, while all the other answers match daylight saving time, which was already in force in New York. We also reread
  the account registry without RepertIA's code, with independent libraries, and the raw values are RepertIA's.
- **Question 6:** for one account NIST does not give the last failed logon attempt, which is in the registry.
- **Question 33:** the Windows event of the burning has number **133**, not 113.
- **Question 30:** the table swaps the modification dates of two files. The Google Drive log and answer 49 give
  RepertIA's dates.
- **Question 38:** NIST names the file `thumbcache_64`, which does not exist in Windows 7. The thumbnails are in
  `thumbcache_256`.

## Defects of RepertIA found with this test, and fixed

1. **Renames in the NTFS journal.** For a file renamed several times, every rename showed the last one's previous name.
   Now each has its own previous name.
2. **False extensions.** An Office document renamed `.amr` or `.svg` was not flagged. Now it is.
3. **Outlook message time.** The delivery time was used, which Outlook records only to the minute for sent messages. The
   sending time is now used, and the delivery time stays in the message text.
4. **Words searched with Internet Explorer and Edge.** Only Chrome's and Firefox's were extracted. They are now also read
   from the Internet Explorer history (Bing, Google, Yahoo, DuckDuckGo…).
5. **Installed programs.** There was only the installation date, without the time. Now there is also the time, from the
   last write of the registry key.
6. **Accounts.** Added the creation date, the last failed logon attempt and the password date.
7. **CDs with 2352-byte sectors.** Only the SHA-256 of the derived copy was recorded. MD5 and SHA-1 are now recorded too,
   the ones published by acquisition tools and by NIST.

For the first two, RepertIA's automatic acceptance test has a new check, also tested the other way round: with the old
code it fails.

## What this test does not say

- **This is not a certification.** NIST did not test RepertIA: we used its public case and its answers.
- **Remaining limits:**
  - messages left in the unused space of Outlook archives are not read, because the library used by RepertIA does not
    offer recovery;
  - the printers configured in the registry and the internal dates of Office documents were not compared.
- **The reasoning questions** stay with the analyst: RepertIA provides the facts, not the conclusions.

## How to repeat the test

1. Download the images with `scarica_nist_leakage.py`, which also checks the SHA-1 hashes published by NIST.
2. Prepare the three cases as described in [tools/prove](../../tools/prove/README.md).
3. Run `valida_nist_leakage.py <cases folder>`: 56 checks, each with the NIST question it refers to.

## Sources

- NIST CFReDS, "Data Leakage Case": <https://cfreds-archive.nist.gov/data_leakage_case/> (images, scenario description,
  answers rev. 1.32 of 2018).
- Scripts: [tools/prove](../../tools/prove/).

*Reports and questions: [repository issues](https://github.com/silvexe/RepertIA/issues).*
