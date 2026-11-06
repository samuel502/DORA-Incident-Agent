# DORA rule sheet

The single source of truth for the rules engine. Every rule in code must point to a line here and to its article. Nothing gets coded that isn't on this sheet.

Rule version: 1.3 (6 November 2026)

Changes in 1.3: section 5 completed with RTS-R Art. 5(2) to 5(6) (late classification, missed deadlines, weekends and bank holidays, and who the weekend rule does not apply to). Section 10 added: the content of the initial notification, from RTS-R Art. 1 and 2 and the template fields in ITS-R Annex II. ITS-R added to the sources. No classification threshold or criterion changed.

Changes in 1.2: open question 8 added (when the downtime and duration of a planned window that overran start), open question 5 extended (what happens when nobody has answered "planned?"), and open question 9 added (T5-b checked on its own, without the "not covered by T5-a" exclusion). All three are interpretations. No threshold or criterion changed.

Changes in 1.1: open questions 4, 5 and 6 added to section 8 (found while mapping `case-library.md`), the daily average method added to open question 6, and the client totals method added as open question 7. No threshold, criterion or rule logic changed.

Verified: Sam checked the spot-check list in section 9 against the official EUR-Lex text on 4 November 2026 (items 1 to 5) and 6 November 2026 (items 6 to 10). All ten match.

## Sources

| Short name | Full name | Used for |
|---|---|---|
| DORA | Regulation (EU) 2022/2554 | The law itself. Art. 18 (classification), Art. 19 (reporting) |
| RTS-C | Commission Delegated Regulation (EU) 2024/1772 | Classification criteria (Art. 1 to 7), when an incident is major (Art. 8), thresholds (Art. 9) |
| RTS-R | Commission Delegated Regulation (EU) 2025/301 | Content of the initial notification (Art. 1, 2), reporting deadlines (Art. 5) |
| ITS-R | Commission Implementing Regulation (EU) 2025/302 | Template (Annex I) and data glossary with field numbers (Annex II) |

Official texts: EUR-Lex. RTS-C was read from the Official Journal version (OJ L, 25.6.2024). RTS-R and ITS-R were read from the Official Journal versions (OJ L, 20.2.2025, both adopted 23 October 2024).

## 1. The big rule: when is an incident major?

**RTS-C Art. 8(1).** An incident is major only if BOTH are true:

1. **Gate:** it affected critical services (see section 2), AND
2. **One of these:**
   - **(a)** the data-loss threshold for malicious access is met (RTS-C Art. 9(5)(b)), OR
   - **(b)** two or more of the other thresholds are met (see section 3)

If the gate is not passed, the incident is not major. Stop there.

In code:

```
major = critical_services_affected AND (T5b OR count(T1, T2, T3, T4, T5a, T6) >= 2)
```

Each threshold counts once, even if several of its points are met. Example: if both 9(1)(a) and 9(1)(b) are met, that is still one threshold (T1).

Background: the RTS explains that a malicious, unauthorised access to systems supporting critical or important functions should always be treated as major (RTS-C recital 10). That's why T5b alone is enough.

## 2. The gate: critical services affected

**RTS-C Art. 6, based on DORA Art. 18(1)(e).** The gate is passed if ANY of these is true:

| ID | Condition |
|---|---|
| G-a | The incident affects or affected ICT services or systems that support **critical or important functions** of the bank |
| G-b | It affects or affected financial services that **require authorisation or registration**, or are supervised by authorities |
| G-c | It is or was a **successful, malicious and unauthorised access** to the bank's network and information systems |

In Rheinbank, G-a comes from the service list (each service is marked critical or not). G-b comes from the service list too (each service is marked regulated or not). G-c comes from security alerts plus human confirmation.

## 3. The six thresholds

### T1. Clients, financial counterparts and transactions

**RTS-C Art. 9(1), criterion from DORA Art. 18(1)(a), details in RTS-C Art. 1.** Met if ANY of these is true:

| ID | Condition |
|---|---|
| T1-a | Affected clients > **10%** of all clients using the affected service |
| T1-b | Affected clients using the affected service > **100,000** |
| T1-c | Affected financial counterparts > **30%** of all counterparts active in the affected service |
| T1-d | Affected transactions > **10%** of the daily average **number** of transactions for the service |
| T1-e | Affected transactions > **10%** of the daily average **value** of transactions for the service |
| T1-f | Clients or counterparts marked as **relevant** (RTS-C Art. 1(3)) were affected |

How to count (RTS-C Art. 1):
- A client counts as affected if they couldn't use the service or were hurt by the incident. This includes third parties named as beneficiaries in the client's contract (Art. 1(1)).
- Counterparts count only if they have a contract with the bank (Art. 1(2)).
- Transactions count if they involve money and at least one part happens in the EU (Art. 1(4)).
- If the real numbers can't be found, they must be **estimated** from comparable past periods (Art. 1(5) and Art. 9(1) last paragraph).

Note: ">" means strictly more than. Exactly 10% does not meet T1-a.

### T2. Reputational impact

**RTS-C Art. 9(2) and Art. 2, criterion from DORA Art. 18(1)(a).** Met if ANY of these is true:

| ID | Condition |
|---|---|
| T2-a | The incident was reported in the **media** |
| T2-b | It caused **repeated complaints** from different clients or counterparts about client-facing services or critical business relationships |
| T2-c | The bank **can't or likely can't meet regulatory requirements** because of it |
| T2-d | The bank **will or likely will lose clients or counterparts**, with a material impact on its business |

### T3. Duration and service downtime

**RTS-C Art. 9(3) and Art. 3, criterion from DORA Art. 18(1)(b).** Met if ANY of these is true:

| ID | Condition |
|---|---|
| T3-a | The incident lasted **longer than 24 hours** |
| T3-b | Service downtime was **longer than 2 hours** for ICT services that support critical or important functions |

How to measure (RTS-C Art. 3):
- **Duration** runs from when the incident happened until it was resolved. If the start is unknown, use the detection time. If logs show it started earlier than detection, use the log time. If the end isn't known yet, estimate (Art. 3(1)).
- **Downtime** runs from when the service became fully or partly unavailable until normal service was restored. If a backlog continues after restoration, downtime runs until the delayed service is fully provided. If the start is unknown, use the detection time (Art. 3(2)).

### T4. Geographical spread

**RTS-C Art. 9(4) and Art. 4, criterion from DORA Art. 18(1)(c).** Met if the incident had an impact in **two or more EU Member States**.

What to look at (Art. 4): clients and counterparts in other Member States, branches or group companies in other Member States, and market infrastructures or third-party providers that serve financial entities in other Member States.

### T5. Data losses

**RTS-C Art. 9(5) and Art. 5, criterion from DORA Art. 18(1)(d).** Two separate thresholds:

| ID | Condition | Counts as |
|---|---|---|
| T5-a | An impact on data **availability, authenticity, integrity or confidentiality** (Art. 5) has or will have an adverse impact on the bank's **business objectives** or its ability to **meet regulatory requirements** | One of the "other" thresholds |
| T5-b | Any **successful, malicious and unauthorised access** to network and information systems (not covered by T5-a) that **may result in data losses** | Alone makes the incident major (if the gate is passed) |

The four data impacts (Art. 5):
- **Availability:** data became temporarily or permanently inaccessible or unusable
- **Authenticity:** the trustworthiness of the data source was compromised
- **Integrity:** data was changed without authorisation and is now inaccurate or incomplete
- **Confidentiality:** data was accessed by or disclosed to an unauthorised party or system

### T6. Economic impact

**RTS-C Art. 9(6) and Art. 7, criterion from DORA Art. 18(1)(f).** Met if costs and losses **exceeded or are likely to exceed €100,000**.

What counts (Art. 7(1)), added up, without subtracting any recoveries:
- Stolen or expropriated funds or assets the bank is liable for
- Replacing or relocating software, hardware or infrastructure
- Staff costs: replacement, extra staff, overtime, recovering lost skills
- Fees for breaking contracts
- Redress and compensation to customers
- Lost revenue
- Internal and external communication costs
- Advisory costs: legal, forensics, remediation

What does not count (Art. 7(2)):
- Normal maintenance and keeping staff skills up to date
- Improvements made after the incident (upgrades, risk assessments)
- Insurance premiums

If actual amounts aren't known, they must be estimated (Art. 7(3)).

## 4. Recurring incidents

**RTS-C Art. 8(2).** Several incidents that are each not major count together as one major incident if ALL are true:
- They happened **at least twice within 6 months**
- They have the **same apparent root cause**
- **Together** they meet the major test in section 1

Banks must check for recurring incidents monthly. This does not apply to microenterprises.

**Status in this project:** out of scope for version 1, because it needs a history of past incidents. Planned for a later version.

## 5. Reporting deadlines (if major)

**DORA Art. 19(4) and RTS-R Art. 5.**

| Report | Deadline |
|---|---|
| Initial notification | Within **4 hours** of classifying the incident as major, and no later than **24 hours** after becoming aware of it |
| Intermediate report | Within **72 hours** of the initial notification |
| Final report | No later than **one month** after the latest intermediate report |

Extra rules in RTS-R Art. 5:

- **Art. 5(1)(a):** the initial notification is due "as early as possible", within 4 hours of classification as major, and no later than 24 hours after the bank became aware of the incident.
- **Art. 5(2), late classification:** if the bank classifies the incident as major only after those 24 hours, the initial notification is due within 4 hours of that classification.
- **Art. 5(3), missed deadline:** if the bank can't meet a deadline, it tells the authority without undue delay, and no later than the deadline, and explains why.
- **Art. 5(4), weekends and bank holidays:** if a deadline falls on a weekend day or a bank holiday in the bank's Member State, the report may be submitted by noon of the next working day.
- **Art. 5(5):** Art. 5(4) does **not** apply to the initial notifications and intermediate reports of credit institutions, central counterparties, trading venue operators, and entities that are essential or important under Art. 3 of Directive (EU) 2022/2555.
- **Art. 5(6):** the authority may also switch off Art. 5(4) for other significant or systemic entities.

Rheinbank is a credit institution (open question 3). So under Art. 5(5), the weekend and bank holiday extension does not apply to its initial notification: the 4 and 24 hour deadline holds on weekends and bank holidays too. The tool says so next to the deadline. For any other kind of entity, the tool does not apply Art. 5(4) and says so.

ITS-R Annex II, field 2.2: the "date and time of detection" is when the bank became aware of the incident. So in this project, "aware" and "detected" are the same moment.

**Status in this project:** the tool shows the initial notification deadline only. Intermediate and final reports are out of scope.

## 6. Facts the agent must collect

The checklist the agent uses to know what to look for. It guides the search. It decides nothing.

| Fact | Feeds | Where Rheinbank keeps it |
|---|---|---|
| Affected service | Gate, T1, T3 | Ticket, service list |
| Is the service critical or important? | G-a, T3-b | Service list |
| Is it a regulated financial service? | G-b | Service list |
| Malicious unauthorised access? | G-c, T5-b | Security alerts, human confirms |
| Affected clients, and total clients of the service | T1-a, T1-b | Client data |
| Affected counterparts, and total | T1-c | Client data |
| Affected transactions (number and value), and daily averages | T1-d, T1-e | Client data |
| Relevant clients or counterparts affected? | T1-f | Client data, human confirms |
| Media coverage, complaints, regulatory or client-loss impact | T2 | Human |
| Start, detection, resolution times | T3-a | Monitoring, ticket |
| Downtime start and restoration | T3-b | Monitoring |
| Countries affected | T4 | Client data, supplier register |
| Data impact (availability, authenticity, integrity, confidentiality) | T5-a | Security alerts, human confirms |
| Adverse impact on business or regulatory compliance? | T5-a | Human |
| Costs and losses so far, or estimate | T6 | Human |
| Outside provider involved? | T4, report | Supplier register |
| When the bank became aware | Deadline | Ticket, monitoring |

## 7. Facts that need a human

Some conditions are judgment calls, not numbers: T1-f, all of T2, T5-a, and whether an access was malicious (G-c, T5-b). For these:

- The AI may suggest an answer and say why.
- A human must confirm it before the rules engine uses it.
- The log records who confirmed it.

If a fact is still unknown, the tool says so and shows which thresholds can't be checked yet. It never guesses silently.

## 8. Open questions to review

These are interpretation points, flagged for review (for example with the PwC contact):

1. **Counting thresholds:** we count each threshold (T1 to T6, with T5-a as its own) once, regardless of how many of its points are met. This follows the wording of Art. 8(1)(b) and Art. 9.
2. **Unknown facts:** the RTS requires estimates where actual numbers can't be found. Version 1 asks the human for an estimate and marks it as an estimate.
3. **Rheinbank as a credit institution:** our fake bank is a bank, so it is not a microenterprise and not one of the simplified-regime entities.
4. **Third-party breaches:** when an attacker got into a supplier's systems, not the bank's, version 1 does not count it as G-c or T5-b for the bank (RTS-C Art. 6(c) refers to the financial entity's own systems). The other criteria decide. Found while mapping `case-library.md` cases C07, C11, C13.
5. **Planned vs unplanned:** DORA Art. 3(8) covers only events unplanned by the financial entity. Version 1 asks the human whether downtime was planned and announced. If fully planned, there is nothing to classify. Found in case C16. If nobody has answered yet: when no planned window is on record, version 1 treats the event as unplanned, because it was reported as an incident; when a planned window is on record, the result stays undetermined until a human answers. This is an interpretation, not a DORA rule. Approved by Sam on 5 November 2026.
6. **Daily averages:** T1-d and T1-e compare against the daily average for the service, not the incident window. Rheinbank's client data must hold daily averages per service. Found in cases C03, C04, C05. Method in version 1: the daily average is taken over the previous calendar month (that month's total divided by its number of days). RTS-C does not fix the period, so this is a bank method choice, not a DORA rule. Approved by Sam on 4 November 2026.
7. **Client totals:** T1-a and T1-c compare affected clients and counterparts against all clients and counterparts using the service (RTS-C Art. 9(1)(a) and (c)). RTS-C does not say on which date to count them. Method in version 1: Rheinbank's client data keeps a yearly snapshot per service, taken on 31 December, and the tool uses the latest snapshot on or before the incident date. This is a bank method choice, not a DORA rule. Approved by Sam on 4 November 2026.
8. **Planned window that overran:** when planned and announced downtime runs past the end of its planned window, the overrun is unplanned, so it is an incident under DORA Art. 3(8) (see open question 5). RTS-C Art. 3(2) does not say when the downtime of such an overrun starts. Method in version 1: the overrun's downtime starts at the planned end of the window and runs until normal service is restored (or the backlog is cleared, as in Art. 3(2)). Downtime inside the planned window does not count. The overrun's duration (RTS-C Art. 3(1)) also starts at the planned end of the window and runs until the incident is resolved. This is an interpretation, not a DORA rule. Found in case C16 (variant B). Approved by Sam on 5 November 2026.
9. **T5-b and T5-a:** RTS-C Art. 9(5)(b) covers a successful, malicious and unauthorised access "not covered by" point (a). Read literally, a breach that meets T5-a would not count as T5-b, and would then need a second threshold to be major. Version 1 does not apply this exclusion: T5-b is checked on its own, whether or not T5-a is met. This follows RTS-C recital 10 (section 1: malicious unauthorised access should always be treated as major) and the case library (C06, C10, C12). Consequence in version 1: a confirmed successful, malicious, unauthorised access to Rheinbank's own systems that may result in data losses is always major. If a human confirms it may not result in data losses, T5-b is not met (it follows the wording of Art. 9(5)(b)), and the other thresholds decide. This is an interpretation, not a DORA rule. Approved by Sam on 5 November 2026.

## 9. Spot-check list for Sam

Check these five lines against EUR-Lex (search "2024/1772 EUR-Lex", German version is fine):

1. Art. 8(1): gate plus "9(5)(b) OR two or more other thresholds"
2. Art. 9(1)(a) and (b): 10% of clients, 100,000 clients
3. Art. 9(3): 24 hours duration, 2 hours downtime
4. Art. 9(6): €100,000
5. Art. 6(c): malicious unauthorised access counts as critical services affected

Added in 1.3. Check against EUR-Lex (search "2025/301 EUR-Lex" or "2025/302 EUR-Lex", Official Journal version of 20.2.2025). In 2025/302 the fields are in Annex II, in the table with the column "Mandatory for initial notification":

6. **Deadline.** RTS-R (2025/301) Art. 5(1)(a) and 5(2). 5(1)(a): initial notification within 4 hours of classification as major, and no later than 24 hours after becoming aware. 5(2): if classified as major only after those 24 hours, within 4 hours of that classification.
7. **No weekend extension for banks.** RTS-R (2025/301) Art. 5(4) and 5(5). 5(4): a deadline on a weekend day or bank holiday moves to noon of the next working day. 5(5): 5(4) does not apply to initial notifications and intermediate reports of credit institutions (and others).
8. **Field 2.2, detection time.** ITS-R (2025/302) Annex II, field 2.2, based on RTS-R Art. 2(b). Mandatory. The moment the bank became aware of the incident, ISO 8601, UTC.
9. **Field 2.5, classification criteria.** ITS-R (2025/302) Annex II, field 2.5, based on RTS-R Art. 2(d). Mandatory, multiple choice of 7: clients, financial counterparts and transactions affected; reputational impact; duration and service downtime; geographical spread; data losses; critical services affected; economic impact.
10. **Field 2.7, discovery.** ITS-R (2025/302) Annex II, field 2.7, based on RTS-R Art. 2(f). Mandatory, one choice of 11: IT security; staff; internal audit; external audit; clients; financial counterparts; third-party provider; attacker; monitoring systems; authority/agency/law enforcement body; other.

## 10. Content of the initial notification

**RTS-R Art. 1 and 2, ITS-R Art. 1 and Annex II.** Field numbers are from ITS-R Annex II. "Mandatory" means the "mandatory for initial notification" column of Annex II.

General rules:

- ITS-R Art. 1(1)(a): for the initial notification, fill in the fields that RTS-R Art. 2 requires. Fields needed only for later reports may be filled in if already known.
- ITS-R Art. 1(2): the information must be complete and accurate.
- ITS-R Art. 1(3): estimates are allowed where accurate data isn't available.
- ITS-R Art. 4: reports go through the secure channel the competent authority provides. (This tool never sends anything. See the build contract.)
- RTS-R recital 2: the initial notification should be limited to the most significant information.

### Section 1: general information (RTS-R Art. 1)

| Field | Name | Initial notification | Notes |
|---|---|---|---|
| 1.1 | Type of submission | Mandatory | Choice: initial notification, intermediate report, final report, major incident reclassified as non-major (RTS-R Art. 1(a)) |
| 1.2 | Name of the entity submitting the report | Mandatory | Full legal name (RTS-R Art. 1(c)) |
| 1.3 | Identification code of the entity submitting the report | Mandatory | LEI, 20 characters, ISO 17442-1:2020 |
| 1.4 | Type of the affected financial entity | Mandatory | Choice of the DORA Art. 2(1) types, for example "credit institution" (RTS-R Art. 1(b)) |
| 1.5 | Name of the financial entity affected | Conditional | Only if it differs from the submitter, or for aggregated reports (RTS-R Art. 1(b), (d)) |
| 1.6 | LEI code of the financial entity affected | Conditional | Same condition as 1.5 |
| 1.7 to 1.9 | Primary contact: name, email, telephone | Mandatory | Telephone with international prefix (RTS-R Art. 1(e)) |
| 1.10 to 1.12 | Second contact: name, email, telephone | Mandatory | May be a team or a functional mailbox |
| 1.13, 1.14 | Ultimate parent undertaking: name, LEI | Conditional | Only if the bank is part of a group (RTS-R Art. 1(f)) |
| 1.15 | Reporting currency | Mandatory | ISO 4217 code (RTS-R Art. 1(g)) |

### Section 2: content of the initial notification (RTS-R Art. 2)

| Field | Name | Initial notification | RTS-R Art. 2 | Notes |
|---|---|---|---|---|
| 2.1 | Incident reference code assigned by the financial entity | Mandatory | (a) | The bank's own unique code |
| 2.2 | Date and time of detection | Mandatory | (b) | When the bank became aware. ISO 8601, UTC |
| 2.3 | Date and time of classification as major | Mandatory | (b) | Classification under RTS-C. ISO 8601, UTC |
| 2.4 | Description of the incident | Mandatory | (c) | High-level overview: possible causes, immediate impacts, systems affected, known or expected impact on third-party providers or other financial entities |
| 2.5 | Classification criteria that triggered the report | Mandatory | (d) | Multiple choice: clients, financial counterparts and transactions affected; reputational impact; duration and service downtime; geographical spread; data losses; critical services affected; economic impact |
| 2.6 | EEA Member States impacted (geographical spread) | Conditional | (e) | Only if the geographical spread threshold (T4) is met. ISO 3166 alpha-2 codes |
| 2.7 | Discovery of the incident | Mandatory | (f) | Choice: IT security, staff, internal audit, external audit, clients, financial counterparts, third-party provider, attacker, monitoring systems, authority/agency/law enforcement body, other |
| 2.8 | Origin in a third-party provider or another financial entity | Conditional | (g) | Only if it originates there. Name and identification code (for example LEI) |
| 2.9 | Activation of business continuity plan | Mandatory | (h) | Yes or no |
| 2.10 | Other relevant information | Conditional | (i), (j) | If there is other relevant information, or if the incident was reclassified as non-major (then the reasons) |

**Status in this project:** field 1.1 is always "initial notification". Reclassification and aggregated reports are out of scope.
