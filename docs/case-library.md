# Case library

Real incidents mapped by hand to the DORA rules in `docs/dora-rules.md`. This is the answer key for testing the rules engine and the agent.

Batch 1 · 4 November 2026 · 17 real cases + 6 constructed cases

## How to read this file

**The rule (from `dora-rules.md` section 1):**

```
major = gate AND (T5-b OR at least 2 of: T1, T2, T3, T4, T5-a, T6)
```

**Status words:**

- **Met:** the public facts clearly show the threshold is met
- **Likely:** the facts point that way, but a number or a judgment is missing. In the tool, a human must confirm.
- **Not met:** the facts show it isn't met
- **Unknown:** no public facts. In the tool, the agent must look it up or ask.

**Three honest limits:**

1. **Not all of these companies fall under DORA.** UK and US cases happened outside the EU, and most happened before DORA applied (17 January 2025). We map them *as if* the firm were an EU financial entity under DORA today. That's a test of the rules, not a legal claim about those firms.
2. **Public cases are biased toward big incidents.** Small incidents rarely make the news, so almost every real case here is major. That's why section 3 adds constructed cases that are not major. They're clearly labeled as made up.
3. **Facts are paraphrased from the sources listed.** Each case lists its sources. Where sources disagree, the case says so.

---

## 1. Summary

| ID | Case | Type | Expected result | Why |
|---|---|---|---|---|
| C01 | TSB IT migration, 2018 | Failed migration | Major | T1, T2, T3, T6 |
| C02 | Postbank IT migration, 2023 | Failed migration | Major | T2, T3 (T6 likely) |
| C03 | TARGET Services outage, 2025 (as a participant bank) | Market infrastructure failure | Major | T3, T4 (T1 likely) |
| C04 | Barclays outage, 2025 | Software fault | Major | T2, T3, T6 (T1 likely) |
| C05 | Visa Europe outage, 2018 | Hardware failure | Major | T2, T3, T4 |
| C06 | ICBC Financial Services ransomware, 2023 | Cyber attack | Major | Gate G-c, T5-b |
| C07 | ION Markets ransomware, 2023 (as a client bank) | Third-party cyber attack | Major | T2, T3 |
| C08 | OP Pohjola DDoS, 2014/15 | DDoS attack | Major | T2, T3 |
| C09 | Bank of Ireland glitch, 2023 | Software fault | Major | T2, T3 |
| C10 | Capital One breach, 2019 | Cyber attack | Major | Gate G-c, T5-b |
| C11 | Flagstar via MOVEit at Fiserv, 2023 | Third-party data breach | Depends on gate | T1, T2 met; gate unclear |
| C12 | Evolve Bank ransomware, 2024 | Cyber attack | Major | Gate G-c, T5-b |
| C13 | Finastra SFTP breach, 2024 (as a client bank) | Third-party data breach | Depends | Gate and data impact unclear |
| C14 | Helaba / FI-TS payment outage, 2019 | Provider failure, backlog | Major | T2, T3 |
| C15 | FI-TS outage hitting DKB, 2023 | Provider failure | Major | T2, T3 |
| C16 | Sparkasse online banking, October 2019 | Planned release | Not an incident, or classify | Planned vs unplanned |
| C17 | CrowdStrike outage, 2024 (two bank variants) | Third-party software fault | Variant A not major, variant B major | Depends on bank |
| N01 | HR portal slow | Constructed | Not major | Gate fails |
| N02 | Short online banking blip | Constructed | Not major | 0 thresholds |
| N03 | Payments down 3 hours, nothing else | Constructed | Not major | Only 1 threshold |
| N04 | Phishing click, no access | Constructed | Not major | No successful access |
| N05 | Short outage, costly and in the news | Constructed | Major | T2, T6 |
| N06 | Exactly 10% of clients | Constructed | Not major | Boundary: 10% is not "more than 10%" |

---

## 2. Real cases

### C01 · TSB IT migration (UK, April 2018)

**What happened:** TSB moved its customer data and systems to a new platform over the weekend of 20 to 22 April 2018. Branch, phone, online and mobile banking failed. Many of its 5.2 million customers couldn't access their accounts. Normal operations only returned on 10 December 2018. TSB received 225,492 complaints and paid £32.7 million in redress. UK regulators later fined it £48.65 million.

| Check | Status | Reason |
|---|---|---|
| Gate | Met | G-a and G-b: core banking channels, regulated services |
| T1 Clients | Met | T1-b: at least 225,492 complainants, so well over 100,000 affected |
| T2 Reputation | Met | T2-a and T2-b: heavy media coverage, mass complaints |
| T3 Duration | Met | T3-a: months |
| T4 Spread | Not met | UK only |
| T5-a Data | Unknown | Not needed |
| T6 Cost | Met | Redress alone far over €100,000 |
| **Result** | **Major** | Gate plus 4 thresholds |

**Agent path:** service list → client data → monitoring → ask human about media and costs → rules.

**Sources:** [FCA Final Notice](https://fs-cp.org.uk/publication/final-notices/tsb-bank-plc-2022.pdf) · [Bank of England news release](https://www.bankofengland.co.uk/news/2022/december/tsb-fined-for-operational-resilience-failings)

---

### C02 · Postbank IT migration (Germany, 2023)

**What happened:** Deutsche Bank migrated about 12 million Postbank customers to its own systems, declared complete in July 2023. Customers were locked out of accounts, online and mobile banking had problems, and the call centres were overwhelmed. BaFin received nearly 10,000 complaints by early September, appointed a special monitor in September 2023, and its president called the situation unacceptable. Problems carried into 2024. Postbank offered compensation of up to €1,000 per case for some delays.

| Check | Status | Reason |
|---|---|---|
| Gate | Met | G-a and G-b: online banking and account services |
| T1 Clients | Unknown | Complaint counts don't show how many clients were affected. Needs an estimate (RTS-C Art. 1(5)) |
| T2 Reputation | Met | T2-a and T2-b: national media, mass complaints |
| T3 Duration | Met | T3-a: months |
| T4 Spread | Not met | Germany |
| T5-a Data | Unknown | Not needed |
| T6 Cost | Likely | Compensation scheme plus remediation; total not public |
| **Result** | **Major** | Gate plus T2 and T3. T1 doesn't need to be known |

**Why it's useful:** the decision can be made even with T1 unknown. The agent should notice that two thresholds are already met and not waste steps.

**Sources:** [Reuters via Investing.com](https://uk.investing.com/news/stock-market-news/deutsche-banks-effort-to-deal-with-complaints-at-postbank-delayed-3275679) · [Börsen-Zeitung](https://www.boersen-zeitung.de/english/sewing-have-not-lived-up-to-our-responsibility) · [vzbv](https://www.vzbv.de/pressemitteilungen/beschwerden-ueber-die-postbank-halten) · [Eulerpool](https://eulerpool.com/en/news/Business/the-postbank-a-subsidiary-of-deutsche-bank-will-be)

---

### C03 · TARGET Services outage (EU, 27 February 2025), seen from a participant bank

**What happened:** A hardware defect took down the Eurosystem's payment and securities settlement platforms. T2 was unavailable for about 10 hours and T2S for about 8 hours. Cut-offs were pushed back by hours. The ECB said it was not a cyber attack. The ESAs' 2025 report names this event as one that triggered a large number of DORA reports.

Mapped from the view of Rheinbank, which settles its large euro payments through T2.

| Check | Status | Reason |
|---|---|---|
| Gate | Met | G-a: payment settlement supports a critical function |
| T1 Clients | Likely | T1-d/e: a day of large payments delayed is likely over 10% of the daily average. Client data must confirm |
| T2 Reputation | Unknown | The outage was in the news, but not about Rheinbank. Human judgment |
| T3 Duration | Met | T3-b: critical service down far longer than 2 hours |
| T4 Spread | Met | RTS-C Art. 4(c): a market infrastructure serving entities in many Member States |
| T5-a Data | Not met | No data loss reported |
| T6 Cost | Unknown | Depends on the bank |
| **Result** | **Major** | Gate plus T3 and T4 |

**Why it's useful:** the cause is outside the bank. The agent should check the supplier register and recognise a cross-border infrastructure.

**Sources:** [Paperjam on the ESA report](https://en.paperjam.lu/article/dora-exposes-3-383-major-ict-incidents-across-eu-financial-sector) · [ECB T2 contact group slides](https://www.ecb.europa.eu/paym/groups/shared/docs/b888b-20260611_t2_cg_item3_2.pdf) · [PaymentsJournal](https://www.paymentsjournal.com/seven-hour-ecb-outage-leaves-trillions-of-euros-in-limbo/?noamp=mobile) · [ESAs 2025 report](https://eba.europa.eu/sites/default/files/2026-06/29b60c21-4ff3-4e1e-9308-7c8225d5cc01/ESAs%202025%20report%20on%20major%20ICT-related%20incidents.pdf)

Note: sources give slightly different durations (about 7 hours in early news, about 10 hours for T2 in later analysis). Both are far over 2 hours, so the result doesn't change.

---

### C04 · Barclays outage (UK, 31 January to 2 February 2025)

**What happened:** A software problem in Barclays' UK mainframe operating system disrupted the app, online banking and payments over three days, including payday and the tax deadline. Barclays has over 13 million digitally active UK customers. On the first day, 5% of login attempts failed, and of those who tried to make a payment, 56% failed. Phone lines had long waits. Barclays expected to pay £5 to £7.5 million in compensation. Not a cyber attack.

| Check | Status | Reason |
|---|---|---|
| Gate | Met | G-a and G-b: online banking and payments |
| T1 Clients | Likely | T1-d: a 56% failure rate on online payments is likely over 10% of the daily average. Needs the daily figures |
| T2 Reputation | Met | T2-a: national media and a parliamentary committee |
| T3 Duration | Met | T3-a: about three days |
| T4 Spread | Not met | UK |
| T5-a Data | Unknown | Not needed |
| T6 Cost | Met | Compensation far over €100,000 |
| **Result** | **Major** | Gate plus T2, T3, T6 |

**Sources:** [Barclays letter to the Treasury Committee](https://committees.parliament.uk/publications/46937/documents/242221/default/) · [Morningstar / Alliance News](https://www.morningstar.co.uk/uk/news/AN_1741250550323280000/barclays-to-pay-up-to-gbp125m-in-compensation-to-customers-.aspx)

---

### C05 · Visa Europe outage (Europe, 1 June 2018)

**What happened:** A rare fault in a data centre switch disrupted card processing from 14:35 until 00:45 the next day, just over 10 hours. Of 51.2 million transactions sent to Visa's European systems in that window, 5.2 million failed. In the UK, 2.4 million transactions failed and about 1.7 million cards were affected. Not a cyber attack. Visa set up a compensation programme.

| Check | Status | Reason |
|---|---|---|
| Gate | Met | G-a: card payment processing |
| T1 Clients | Likely | About 10.2% of transactions in the window failed. T1-d compares to the *daily average*, which isn't public. Borderline, so the human must confirm |
| T2 Reputation | Met | T2-a: international media, parliamentary inquiry |
| T3 Duration | Met | T3-b: critical service disrupted about 10 hours |
| T4 Spread | Met | Failures across many European countries |
| T5-a Data | Not met | No data loss reported |
| T6 Cost | Likely | Compensation programme; amount not public |
| **Result** | **Major** | Gate plus T2, T3, T4 |

**Why it's useful:** T1 sits right at the 10% line. The agent shouldn't guess. It doesn't matter for the result, since three other thresholds are met.

**Sources:** [Computer Weekly](https://www.computerweekly.com/news/252443325/Visa-reveals-rare-datacentre-switch-fault-as-root-cause-of-June-2018-outage) · [FinanceFeeds](https://financefeeds.com/visa-hires-external-party-conduct-review-latest-system-failure-replies-uk-treasury-committee/) · [Inkl / Guardian](https://www.inkl.com/news/visa-admits-5m-payments-failed-over-a-broken-switch)

---

### C06 · ICBC Financial Services ransomware (US, November 2023)

**What happened:** The US broker-dealer arm of ICBC was hit by ransomware on 8 November 2023. It couldn't settle US Treasury trades for other market participants, and some equity trades were affected. Reports linked the attack to LockBit and an unpatched Citrix vulnerability. Market impact was described as limited.

| Check | Status | Reason |
|---|---|---|
| Gate | Met | G-c: successful, malicious, unauthorised access |
| T5-b | Met | Malicious access that may result in data loss |
| Others | Not needed | |
| **Result** | **Major** | Gate plus T5-b alone |

**Why it's useful:** the shortest major path. Once malicious access is confirmed, the agent can stop collecting and go to the rules.

**Agent path:** security alerts first → human confirms malicious access → rules.

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/worlds-largest-commercial-bank-icbc-confirms-ransomware-attack/) · [Security Affairs](https://securityaffairs.com/153986/hacking/icbc-ransomware-attack.html) · [Computer Weekly](https://www.computerweekly.com/news/366559013/Ransomware-attack-on-major-Chinese-lender-disrupts-financial-markets)

---

### C07 · ION Markets ransomware (global, from 31 January 2023), seen from a client bank

**What happened:** Ransomware hit ION Cleared Derivatives, a provider of trading and clearing software. At least 42 clients were affected, reportedly including ABN Amro Clearing and Intesa Sanpaolo. Banks had to process derivatives trades manually. ION told clients systems wouldn't be fully running until 6 February. Regulators in the US and UK commented publicly.

Mapped from the view of a client bank whose own systems were not breached.

| Check | Status | Reason |
|---|---|---|
| Gate | Met | G-a: derivatives clearing supported by an ICT third-party service |
| G-c / T5-b | Open question | The access was to ION's systems, not the bank's. RTS-C Art. 6(c) says "the financial entity's" systems. See open question 4 |
| T1 Clients | Unknown | Depends on the bank's client and trade data |
| T2 Reputation | Met | T2-a: the incident was widely reported |
| T3 Duration | Met | T3-a and T3-b: several days |
| T4 Spread | Unknown | Depends on where the bank's clients are |
| **Result** | **Major** | Gate plus T2 and T3, even without T5-b |

**Agent path:** ticket mentions vendor → supplier register → monitoring → ask human about media → rules.

**Sources:** [Securities Finance Times](https://www.securitiesfinancetimes.com/securitieslendingnews/swaparticle.php?article_id=226077) · [CFTC statement](https://www.cftc.gov/PressRoom/SpeechesTestimony/cftcstatement020223) · [The Register](https://www.theregister.com/2023/02/03/ion_ransomware_attack/) · [FinanceFeeds](https://financefeeds.com/cftc-comments-on-ion-cleared-derivatives-issues-after-russian-linked-hack/)

---

### C08 · OP Pohjola DDoS (Finland, 31 December 2014 onwards)

**What happened:** A denial-of-service attack flooded OP's network from about 16:30 on New Year's Eve. Online services were down, ATM cash withdrawals failed and card payments had problems. Disruption for customers abroad continued for about six days. OP reported it to the police and promised compensation for fees and losses.

| Check | Status | Reason |
|---|---|---|
| Gate | Met | G-a: online banking, ATMs and cards |
| G-c / T5-b | Not met | A DDoS floods systems but doesn't access them. No unauthorised access |
| T1 Clients | Unknown | Not public |
| T2 Reputation | Met | T2-a: national media, police investigation |
| T3 Duration | Met | T3-a: disruption over several days |
| T4 Spread | Unknown | Customers abroad affected; whether in other Member States and how significant isn't clear |
| **Result** | **Major** | Gate plus T2 and T3 |

**Why it's useful:** a malicious attack that is *not* "unauthorised access." The agent must not jump to T5-b just because it's a cyber attack. Good test of the difference.

**Note:** this happened in 2014/15, long before DORA. Kept because the facts are well documented.

**Sources:** [OP statement via MarketScreener](https://ca.marketscreener.com/quote/stock/POHJOLA-BANK-PLC-1412504/news/Pohjola-Bank-OP-suffered-from-a-denial-of-services-attack-on-New-Year-s-Eve-19609310) · [Yle](https://yle.fi/a/3-7720113) · [Help Net Security](https://helpnetsecurity.com/?p=38107)

---

### C09 · Bank of Ireland glitch (Ireland, 15 to 16 August 2023)

**What happened:** An hours-long technical fault disrupted the app, online banking and phone banking. During the fault, some customers could transfer or withdraw more than their balance, up to about €1,000. Queues formed at ATMs and police were called. The bank said it wasn't a cyber attack. The Central Bank of Ireland and the finance minister asked for a full account. The bank had been fined €24.5 million in 2021 for IT continuity failings.

| Check | Status | Reason |
|---|---|---|
| Gate | Met | G-a and G-b: core digital banking |
| T1 Clients | Unknown | Not public |
| T2 Reputation | Met | T2-a and T2-c: national media, regulator and minister involved |
| T3 Duration | Met | T3-b: critical services down for hours |
| T5-a Data | Likely | Balances and limits were wrong, which is an integrity problem. Human judgment on business impact |
| T6 Cost | Unknown | Overdrawn amounts weren't disclosed |
| **Result** | **Major** | Gate plus T2 and T3 |

**Why it's useful:** an EU bank, and the data problem isn't a hack. Integrity can be hit by a bug.

**Sources:** [RTÉ](https://www.rte.ie/news/business/2023/0816/1399974-bank-of-ireland) · [TechCentral.ie](https://techcentral.ie/bank-of-ireland-says-technical-issues-have-been-resolved) · [Irish Times](https://irishtimes-irishtimes-prod.cdn.arcpublishing.com/your-money/2024/04/04/bank-of-ireland-working-to-resolve-online-and-mobile-banking-outage/)

---

### C10 · Capital One breach (US, March 2019, disclosed July 2019)

**What happened:** An attacker exploited a misconfigured web application firewall in Capital One's cloud environment and stole about 100 million US and 6 million Canadian credit card applications, including Social Security and bank account numbers. It happened in March 2019 and was found about four months later.

| Check | Status | Reason |
|---|---|---|
| Gate | Met | G-c: successful, malicious, unauthorised access |
| T5-b | Met | |
| **Result** | **Major** | Gate plus T5-b |

**Why it's useful:** the incident started months before it was found. Under RTS-C Art. 3(1), duration is measured from when the logs show it started, not from detection. Tests the duration rule.

**Sources:** [Corbado](https://www.corbado.com/blog/data-breaches-finance) · [Atlas Systems](https://www.atlassystems.com/blog/cybersecurity-breaches-in-banking) · [UpGuard](https://www.upguard.com/blog/biggest-data-breaches-financial-services)

---

### C11 · Flagstar Bank via MOVEit at Fiserv (US, 2023)

**What happened:** Attackers exploited the MOVEit Transfer vulnerability at Fiserv, a Flagstar supplier. Names, addresses, phone numbers, Social Security numbers and tax records of 837,390 Flagstar customers were exposed. Flagstar's own systems were not the ones breached.

| Check | Status | Reason |
|---|---|---|
| Gate | Open question | Flagstar's own systems weren't accessed (so not G-c). Whether the vendor's file transfer supports a critical function of the bank (G-a) is a human judgment |
| T1 Clients | Met | T1-b: 837,390 clients adversely affected (RTS-C Art. 1(1) counts clients hurt by the incident) |
| T2 Reputation | Met | T2-a: national media |
| T5-a Data | Likely | Confidentiality breach with business and regulatory impact |
| **Result** | **Depends on the gate** | If the gate is passed: major (T1, T2). If not: not major |

**Why it's useful:** everything hinges on one judgment. The agent must ask the human a precise question about the gate, not guess.

**Sources:** [Atlas Systems](https://www.atlassystems.com/blog/cybersecurity-breaches-in-banking) · [UpGuard](https://www.upguard.com/blog/biggest-data-breaches-financial-services)

---

### C12 · Evolve Bank & Trust ransomware (US, February to May 2024)

**What happened:** LockBit got in on 9 February 2024 after an employee clicked a malicious link. Evolve found systems "not working properly" on 29 May and first thought it was a hardware failure. Data of 7,640,112 people was stolen, including names, Social Security numbers, account numbers and some debit card numbers. Fintech partners like Wise and Affirm were affected.

| Check | Status | Reason |
|---|---|---|
| Gate | Met | G-c: successful, malicious, unauthorised access |
| T5-b | Met | |
| **Result** | **Major** | Gate plus T5-b |

**Why it's useful:** it was first misread as a hardware failure. A good test: the same incident should be re-classified once security alerts show malicious access. It also has about four months of dwell time, which tests the duration rule like C10.

**Sources:** [Evolve's own notice](https://www.getevolved.com/about/news/cybersecurity-incident/) · [BleepingComputer](https://www.bleepingcomputer.com/news/security/evolve-bank-says-data-breach-impacts-76-million-americans/) · [The Register](https://www.theregister.com/2024/07/09/evolve_lockbit_attack)

---

### C13 · Finastra SFTP breach (global, 31 October to 8 November 2024), seen from a client bank

**What happened:** Using compromised credentials, an attacker accessed a secure file transfer platform that Finastra, a software supplier to most of the world's largest banks, uses to send files to some customers. About 400 GB of data was offered for sale. Finastra said there was no direct impact on customer operations or customers' systems.

Mapped from the view of a client bank that used this platform.

| Check | Status | Reason |
|---|---|---|
| Gate | Unknown | Not the bank's systems (not G-c). Does the file transfer support a critical function? Human |
| T1 Clients | Unknown | Depends on whose data was in the bank's files |
| T5-a Data | Unknown | Depends on what the bank's files contained |
| T2 Reputation | Unknown | The breach was in the news, but not necessarily naming this bank |
| **Result** | **Depends** | Could easily be not major |

**Why it's useful:** a realistic case where the right answer is "I need more facts." The agent must list what's missing instead of producing a confident result.

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/fintech-giant-finastra-notifies-victims-of-october-data-breach/) · [TechMonitor](https://techmonitor.ai/?p=412048) · [CSO Online](https://www.csoonline.com/article/3610267/finastra-investigates-breach-potentially-affecting-top-global-banks.html)

---

### C14 · Helaba / FI-TS payment outage (Germany, 5 December 2019)

**What happened:** A technical fault at FI-TS, an IT provider in the Sparkasse group, stopped SEPA transfers, direct debits and card transactions processed via Helaba on Thursday 5 December. After the fix, more unprocessed transaction files were found. Tens of thousands of Sparkasse customers were missing salaries, child benefit and other payments for days. Helaba promised to reimburse proven losses. A cyber attack was ruled out.

| Check | Status | Reason |
|---|---|---|
| Gate | Met | G-a: payments |
| T1 Clients | Unknown | "Tens of thousands" of customers; share of the service's clients not public |
| T2 Reputation | Met | T2-a and T2-b: national media, many complaints |
| T3 Duration | Met | T3-a and T3-b: the backlog ran for days |
| T6 Cost | Unknown | Reimbursements not totalled publicly |
| **Result** | **Major** | Gate plus T2 and T3 |

**Why it's useful:** tests RTS-C Art. 3(2). Downtime doesn't end when the system is back up. It ends when the delayed payments are fully processed.

**Sources:** [Helaba press release](https://www.Sparkasse-MagdeBurg.de/content/dam/myif/spk-magdeburg/work/dokumente/pdf/pressecenter/26_2019.pdf?n=true) · [Berliner Zeitung](https://www.berliner-zeitung.de/article/it-problem-betrifft-auch-koeln-mehrere-zehntausend-sparkassen-kunden-betroffen-37159) · [leinetal24](https://www.leinetal24.de/verbraucher/sparkassen-stoerung-konto-problem-geld-kein-gehalt-ueberweisung-rechnung-zr-13284590.html)

---

### C15 · FI-TS outage hitting DKB (Germany, 25 October 2023)

**What happened:** A technical fault at FI-TS took down DKB's online banking from around midday, still unresolved by 19:00. DKB's email system was also hit. Helaba and other institutions were affected too. DKB is an online-only bank.

| Check | Status | Reason |
|---|---|---|
| Gate | Met | G-a: online banking is DKB's main channel |
| T1 Clients | Unknown | Likely high for an online-only bank, but not public |
| T2 Reputation | Met | T2-a: reported by Handelsblatt, plus social media complaints |
| T3 Duration | Met | T3-b: critical service down for many hours |
| T4 Spread | Unknown | |
| **Result** | **Major** | Gate plus T2 and T3 |

**Note:** the main source is a tech blog, which cites Handelsblatt. Facts are thinner than other cases. Flagged for replacement or extra sources in batch 2.

**Sources:** [Born's Tech and Windows World](https://borncity.com/blog/2023/10/25/online-banking-bei-dkb-gestrt-25-10-2023/)

---

### C16 · Sparkasse online banking (Germany, 12 to 14 October 2019)

**What happened:** From Saturday evening, many Sparkasse customers couldn't log into online banking, and some couldn't withdraw cash. Reports continued into Monday. The IT provider Finanz Informatik said it wasn't a fault but planned interruptions for a new release, announced by the individual Sparkassen.

| Check | Status | Reason |
|---|---|---|
| Is it an ICT-related incident? | Depends | DORA Art. 3(8) defines an incident as an event *unplanned* by the financial entity. Planned maintenance isn't one |
| **Result** | **Not an incident, if fully planned.** If the outage ran beyond the planned window or hit more than planned, the overrun is an incident and must be classified |

**Why it's useful:** the first question isn't "major or not" but "is this an incident at all." The agent must ask whether the downtime was planned and announced.

**Sources:** [PC-Welt](https://www.pcwelt.de/news/Sparkasse-Stoerung-Online-Banking-und-Geld-abheben-gehen-nicht-mehr-10683329.html) · [PC-Welt follow-up](https://www.pcwelt.de/news/Stoerung-bei-der-Sparkasse-Der-Grund-fuer-den-Ausfall-10683736.html)

---

### C17 · CrowdStrike outage (global, 19 July 2024), two bank variants

**What happened:** A faulty CrowdStrike content update crashed about 8.5 million Windows devices worldwide. CrowdStrike rolled it back within about 90 minutes, but affected machines had to be fixed by hand. Banks reported problems, and some trading desks couldn't log in. Not a cyber attack. US industry groups said the financial sector had no systemic impact.

Same event, two different banks:

**Variant A:** Rheinbank's office laptops crash for 4 hours. Online banking, payments and cards keep running on unaffected servers.

| Check | Status | Reason |
|---|---|---|
| Gate | Not met | No critical or important function affected |
| **Result** | **Not major** | Gate fails |

**Variant B:** Rheinbank's payment operations workstations in Germany and Austria are down for 5 hours. Payments queue up.

| Check | Status | Reason |
|---|---|---|
| Gate | Met | G-a: payment operations |
| T3 Duration | Met | T3-b: over 2 hours |
| T4 Spread | Met | Two Member States |
| **Result** | **Major** | Gate plus T3 and T4 |

**Why it's useful:** proves the tool classifies the *bank's* incident, not the headline. Variant details are constructed on top of the real event.

**Sources:** [Consilien](https://consilien.com/news/the-great-crowdstrike-outage-a-detailed-dive-into-what-happened-and-its-far-reaching-effects) · [ICBA](https://icba.org/newsroom/news-details/2024/07/19/ceo-alert-crowdstrike-it-outage) · [NYSSCPA](https://nysscpa.org/news/1046006-major-tech-outage-affects-financial-firms-along-with-other-businesses-2024-07-19)

---

## 3. Constructed cases

Made up on purpose. They fill the gap that public cases leave: incidents that are *not* major, and exact boundary tests. Each tests one rule.

### N01 · HR portal slow

Rheinbank's internal HR portal is slow for a morning. No clients affected.

- Gate: not met (HR isn't critical or regulated) → **Not major.** Two steps.

### N02 · Short online banking blip

Online banking unavailable for 40 minutes on a Tuesday afternoon. About 3% of online banking clients affected. No media, a handful of complaints, no data loss, costs about €5,000.

- Gate: met. T1: not met (3%, under 100,000). T2: not met. T3: not met (under 2 hours). T6: not met. → **Not major.** Zero thresholds.

### N03 · Payments down 3 hours, nothing else

Outgoing SEPA payments stop for 3 hours and are then processed normally. 4% of the day's payments delayed. No media, no data loss, costs about €20,000. Germany only.

- Gate: met. T3-b: met. Everything else: not met. → **Not major.** Only one threshold, and it needs two. This is the test that catches the "any single threshold" mistake.

### N04 · Phishing click, no access

An employee clicks a phishing link. The security team confirms the login attempt was blocked and nothing was accessed.

- G-c: not met (no *successful* access). T5-b: not met. Other services unaffected. → **Not major.** Could be a voluntary cyber threat notification under DORA Art. 19(2), which is out of scope.

### N05 · Short outage, costly and in the news

Card payments fail for 90 minutes during a Saturday shopping peak. National news covers it. Emergency vendor support and customer refunds cost about €140,000.

- Gate: met. T2: met. T3: not met (under 2 hours). T6: met. → **Major.** Two thresholds, even though the outage was short.

### N06 · Exactly 10% of clients

Mobile banking login fails for exactly 10.0% of the clients who use it, for 70 minutes. Nothing else.

- Gate: met. T1-a: **not met**, since the rule says *more than* 10%. → **Not major.** Boundary test for strict comparisons.

---

## 4. Open questions found while mapping

Added to the open questions in `dora-rules.md` section 8.

4. **Third-party breaches (C07, C11, C13):** when the attacker got into a supplier's systems, not the bank's, does G-c or T5-b apply to the bank? RTS-C Art. 6(c) refers to the financial entity's own systems. Version 1 treats it as **not** G-c/T5-b, and lets the other criteria decide. Good question for the PwC contact.
5. **Planned vs unplanned (C16):** version 1 asks the human whether downtime was planned and announced. If yes, no classification.
6. **Daily averages for T1-d/e (C03, C04, C05):** the rule compares to the *daily average*, not the incident window. The client data in Rheinbank must hold daily averages per service.

## 5. Next batch

Candidates with good public facts still to add:

- Iberian Peninsula blackout, April 2025 (external event, named in the ESA report)
- Lloyds and Halifax outage, February 2025 (short, under 24 hours)
- More EU cases from 2025 and 2026, now that DORA applies
- More not-major and boundary cases, since real ones are rare in public sources

Then the testing block turns every case into variations: missing facts, different numbers, confusing wording.
