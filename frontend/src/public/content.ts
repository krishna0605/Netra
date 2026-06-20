export const publicUpdates = [
  {
    version: "01",
    date: "INDIA / 2024",
    title: "The public cyber-fraud landscape",
    body: "Everyday cybercrime increasingly begins with social engineering rather than a technical exploit. Fraudsters manufacture urgency, authority, reward, or fear, then move the victim toward a payment, credential handoff, screen-share, or malicious installation.",
    note: "NCRP figures reported for 2024 recorded 22.68 lakh cybercrime complaints and about Rs 22,845.73 crore in reported losses. These are reported complaints and amounts, not a measure of all victimisation.",
    visual: "landscape",
    metrics: [["22.68L", "complaints reported"], ["Rs 22,845.73 Cr", "reported amount"], ["1930", "financial-fraud helpline"]],
    signals: ["Investment and trading fraud", "Impersonation and digital arrest", "Phishing, KYC and account takeover", "UPI collect and remote-access scams"],
    details: [
      ["Highest public-facing risk", "Financial fraud driven by impersonation and social engineering is the broadest everyday risk pattern."],
      ["Read the number carefully", "Complaint totals include reports made through the National Cyber Crime Reporting Portal; one incident may involve several contacts or transactions."],
    ],
    source: "I4C / National Cyber Crime Reporting Portal",
    sourceUrl: "https://cybercrime.gov.in/",
  },
  {
    version: "02",
    date: "ATTACK PATH",
    title: "How common attacks reach ordinary people",
    body: "The channel changes, but the sequence is remarkably consistent: a convincing approach, a pressure tactic, an action that transfers control or money, and deliberate friction that delays reporting.",
    note: "Digital arrest calls, fake investment groups, parcel or KYC warnings, task scams, loan-app abuse, QR or UPI collect requests, and remote-support apps are recurring public advisories across India.",
    visual: "path",
    metrics: [["01", "approach"], ["02", "pressure"], ["03", "payment or access"]],
    signals: ["Unknown call, ad or message", "Authority, fear, scarcity or profit", "OTP, PIN, UPI approval or screen-share", "Isolation and repeated transfer demands"],
    details: [
      ["Digital arrest", "No legitimate police or court process demands secrecy, continuous video supervision, or a transfer to a so-called safe account."],
      ["UPI and QR traps", "Receiving money does not require a UPI PIN. Entering the PIN approves a debit from the account."],
      ["Investment and task scams", "Small early payouts can be used to build trust before larger deposits are blocked or further fees are demanded."],
    ],
    source: "Indian Cyber Crime Coordination Centre advisories",
    sourceUrl: "https://i4c.mha.gov.in/",
  },
  {
    version: "03",
    date: "PEOPLE / STATES",
    title: "Different hooks, the same nationwide threat",
    body: "There is no single victim profile. Students and first-job seekers may see task or recruitment fraud; working adults may face investment, courier, KYC, or business impersonation; older adults may receive authority, pension, insurance, or remote-support approaches.",
    note: "Gujarat is part of the same cross-state fraud ecosystem as every other state and union territory. Targeting follows access, trust, language, financial behaviour, and exposed personal data more than a state boundary.",
    visual: "people",
    metrics: [["18-25", "study, jobs, gaming"], ["26-59", "payments, work, investing"], ["60+", "authority, support, benefits"]],
    signals: ["Gujarat and western India", "North, south, east and central India", "Urban, semi-urban and rural users", "Hindi, English and regional-language lures"],
    details: [
      ["If money moved", "Call 1930 immediately, contact the bank or payment provider, and submit the complaint at cybercrime.gov.in."],
      ["Preserve evidence", "Keep transaction IDs, phone numbers, usernames, URLs, screenshots, emails and timestamps. Do not delete the conversation."],
      ["Avoid victim blame", "Well-designed fraud manipulates normal human trust and urgency. Fast reporting and clear evidence matter more than embarrassment."],
    ],
    source: "National Cyber Crime Reporting Portal / Citizen Financial Cyber Fraud Reporting",
    sourceUrl: "https://cybercrime.gov.in/",
  },
  {
    version: "04",
    date: "FIRST RESPONSE",
    title: "The first minutes after financial fraud",
    body: "Stop communicating with the suspected fraudster, do not send a second payment, and do not install any app they suggest. Use a separate trusted device where possible to contact the bank, wallet, card issuer, or payment provider.",
    note: "Call 1930 as soon as possible when money has moved or account access may be compromised. Give the operator the transaction reference, amount, time, beneficiary details, and the acknowledgement supplied by the bank or payment service.",
    visual: "response",
    metrics: [["00:00", "stop contact"], ["00:05", "call 1930"], ["00:10", "alert payment provider"]],
    signals: ["Freeze cards, UPI or online banking if needed", "Reset exposed passwords from a clean device", "Revoke remote-access and unknown sessions", "Write down the incident while details are fresh"],
    details: [
      ["Money was transferred", "Call 1930, contact the payment provider, and file the full online complaint. Fast reporting may help authorities and banks act on the transaction trail."],
      ["Credentials were exposed", "Change the affected password and every reused password, enable multi-factor authentication, and review recovery email, phone and active sessions."],
      ["A device was controlled", "Disconnect it from the network, do not wipe it immediately, photograph visible messages, and seek trusted technical assistance before using it for banking."],
    ],
    source: "National Cyber Crime Reporting Portal helpline guidance",
    sourceUrl: "https://cybercrime.gov.in/Webform/Helpline.aspx",
  },
  {
    version: "05",
    date: "COMPLAINT GUIDE",
    title: "How to register a cybercrime complaint",
    body: "Open the National Cyber Crime Reporting Portal, choose the reporting route that fits the incident, sign in with the requested mobile verification, and describe what happened in chronological order. Use accurate facts and mark assumptions as assumptions.",
    note: "Add the communication channel, suspect identifiers, transaction information, dates, times, URLs, and the state or district connected with the incident. Upload readable evidence and retain the acknowledgement number for status checks and police follow-up.",
    visual: "complaint",
    metrics: [["01", "open the portal"], ["02", "record the incident"], ["03", "save acknowledgement"]],
    signals: ["Visit cybercrime.gov.in directly", "Select the relevant complaint category", "Enter incident and transaction details", "Upload evidence and note the reference number"],
    details: [
      ["Before you begin", "Keep a working mobile number, incident timeline, suspect contact details, transaction references, screenshots, emails and identity information required by the portal ready."],
      ["Write a useful narrative", "State who contacted you, when and how; what they claimed; what action was requested; what you did; and what money, account or device access was affected."],
      ["After submission", "Save the acknowledgement, check complaint status through the official portal, respond to police requests, and preserve the original evidence without editing it."],
    ],
    source: "National Cyber Crime Reporting Portal",
    sourceUrl: "https://cybercrime.gov.in/",
  },
  {
    version: "06",
    date: "HELP CHANNELS",
    title: "Know which official help channel to use",
    body: "Different numbers serve different needs. Use 1930 for financial cyber fraud. Use 112 when there is immediate danger or an urgent physical-safety concern. Children can seek assistance through Child Helpline 1098, while the Women Helpline programme uses 181 for support and referral.",
    note: "A helpline call does not always replace the full cybercrime complaint. For cyber incidents, complete the record at cybercrime.gov.in and follow instructions from the bank, portal, police, or relevant support service.",
    visual: "helplines",
    metrics: [["1930", "financial cyber fraud"], ["112", "emergency response"], ["1098", "child helpline"]],
    signals: ["181 - Women Helpline support and referral", "Local bank or payment-provider fraud desk", "Nearest police or cybercrime police station", "cybercrime.gov.in - online complaint and status"],
    details: [
      ["1930", "Use for financial cyber fraud and report the transaction trail promptly. Keep the full complaint acknowledgement and bank reference together."],
      ["112 / 1098 / 181", "Use 112 for immediate emergency assistance, 1098 for a child needing care or protection, and 181 for Women Helpline support. Availability and service routing can vary by location."],
      ["Evidence checklist", "Preserve original messages, emails, call logs, usernames, phone numbers, URLs, QR codes, payment references, bank statements, screenshots and a written timeline."],
    ],
    source: "Official Government of India cybercrime and support services",
    sourceUrl: "https://cybercrime.gov.in/",
  },
];

export const capabilityRows = [
  { number: "01", title: "Capture", body: "Register PCAP evidence or collect from managed sensors with case, source, and custody context." },
  { number: "02", title: "Decode", body: "Reconstruct sessions and inspect DNS, HTTP, TLS, FTP, SMTP, ICMP, TCP, and UDP evidence." },
  { number: "03", title: "Detect", body: "Run explainable signatures for tunnels, beaconing, exfiltration, malware C2, scans, and remote activity." },
  { number: "04", title: "Analyze", body: "Compare observed behaviour with baselines and surface model limitations alongside anomaly indicators." },
  { number: "05", title: "Investigate", body: "Connect alerts, packets, sessions, hosts, notes, and attack paths inside a case-scoped workspace." },
  { number: "06", title: "Report", body: "Generate evidence-aware reports, exports, hashes, and custody records in three investigation languages." },
];

export const faqRows = [
  {
    question: "Does NETRA decrypt protected traffic?",
    answer: "No. NETRA studies observable connection metadata and behaviour. It does not claim access to encrypted payload content.",
  },
  {
    question: "Can NETRA analyze a real packet capture?",
    answer: "Yes. The investigation workflow accepts PCAP evidence and produces packet, session, protocol, detection, anomaly, graph, and report records through the backend analysis pipeline.",
  },
  {
    question: "How is evidence integrity represented?",
    answer: "Evidence intake records a SHA-256 digest and case context. Custody events, access history, reports, and exports remain linked to the active investigation.",
  },
  {
    question: "Does an AI anomaly automatically confirm an attack?",
    answer: "No. An anomaly is an investigator-review signal. NETRA exposes contributing evidence, model mode, fallback status, and limitations so a person can make the final determination.",
  },
  {
    question: "Which languages are supported?",
    answer: "The investigation interface and reporting workflow support English, Hindi, and Gujarati for regional cybercrime operations.",
  },
];

export const integrationRows = [
  ["SIEM export", "Move structured findings into an existing security operations workflow."],
  ["Webhooks", "Deliver case-scoped alerts to approved downstream systems."],
  ["Sensor fleet", "Coordinate capture agents, interfaces, schedules, and health signals."],
  ["Encrypted storage", "Keep generated reports and evidence artifacts behind authenticated routes."],
  ["Search indexing", "Locate investigation records without detaching them from case context."],
  ["Multilingual reports", "Prepare investigator-facing outputs in English, Hindi, and Gujarati."],
] as const;
