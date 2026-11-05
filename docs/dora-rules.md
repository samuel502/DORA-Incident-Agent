# DORA rule sheet

The single source of truth for the rules engine. Every rule in code must point to a line here and to its article. Nothing gets coded that isn't on this sheet.

Rule version: 1.0 (4 November 2026)

Verified: Sam checked the spot-check list in section 9 against the official EUR-Lex text on 4 November 2026. All five match.

## Sources

| Short name | Full name | Used for |
|---|---|---|
| DORA | Regulation (EU) 2022/2554 | The law itself. Art. 18 (classification), Art. 19 (reporting) |
| RTS-C | Commission Delegated Regulation (EU) 2024/1772 | Classification criteria (Art. 1 to 7), when an incident is major (Art. 8), thresholds (Art. 9) |
| RTS-R | Commission Delegated Regulation (EU) 2025/301 | Reporting deadlines (Art. 5) |

Official texts: EUR-Lex. RTS-C was read from the Official Journal version (OJ L, 25.6.2024).

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

Extra rules in RTS-R Art. 5: if a deadline falls on a weekend or bank holiday, special rules apply (submission by noon of the next working day in some cases). If a bank can't meet a deadline, it must tell the authority and explain why.

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
5. **Planned vs unplanned:** DORA Art. 3(8) covers only events unplanned by the financial entity. Version 1 asks the human whether downtime was planned and announced. If fully planned, there is nothing to classify. Found in case C16.
6. **Daily averages:** T1-d and T1-e compare against the daily average for the service, not the incident window. Rheinbank's client data must hold daily averages per service. Found in cases C03, C04, C05.

## 9. Spot-check list for Sam

Check these five lines against EUR-Lex (search "2024/1772 EUR-Lex", German version is fine):

1. Art. 8(1): gate plus "9(5)(b) OR two or more other thresholds"
2. Art. 9(1)(a) and (b): 10% of clients, 100,000 clients
3. Art. 9(3): 24 hours duration, 2 hours downtime
4. Art. 9(6): €100,000
5. Art. 6(c): malicious unauthorised access counts as critical services affected
