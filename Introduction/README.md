# Introduction to Penetration testing

## Penetration Testing

Visual

![HackTheBox](https://academy.hackthebox.com/storage/modules/90/0-PT-Process.png)

- An audit process aiming to uncover **ALL** vulnerabilities in a system.
- It is also a part of the Security Risk management process.
- During a pentest, detailed documentation is important as it can highlight almost every important system flaw. But it is the client's responsibility to rectify all issues identified and highlighted in the report.

## Vulnerability Assessment

- Unlike a pentest, Vulnerability Assessments are purely done using automated tools like Nessus, Qualys, OpenVAS, etc.
- They detect preconfigured vulnerabilities and usually cannot adapt the attacks to the configuration of the target system.
- This is usually why manual penetration testing is always a plus, because a manual pentester can adapt attacks to the system.

## Testing methods

There are usually 2 types, internal or external pentests.

### External Pentest

- Done externally, in the perspective of an anonymous user on the internet.
- Clients may specify various requirements, like to be stealthy (using all possible evasion tactics), hybrid (become noisier as the test goes on) or noisy (stealth not required).

### Internal Pentest

- Done from within the corporate network, with the assumption that the breach has already occured or that the threat is from within.
-  Internal pentests may also access isolated systems with no internet access whatsoever, which usually requires our physical presence at the client's facility.

## Laws and Regulations

Refer to the HTB table 

### Precautionary measures during penetration tests

- [ ] Obtain written consent from the owner or authorized representative of the computer or network being tested  
- [ ] Conduct the testing within the scope of the consent obtained only and respect any limitations specified  
- [ ] Take measures to prevent causing damage to the systems or networks being tested  
- [ ] Do not access, use or disclose personal data or any other information obtained during the testing without permission  
- [ ] Do not intercept electronic communications without the consent of one of the parties to the communication  
- [ ] Do not conduct testing on systems or networks that are covered by the Health Insurance Portability and Accountability Act (HIPAA) without proper authorization  

## Penetration Testing Process

Again, peek this sick visual 

![Sorry, forgot to load image](https://academy.hackthebox.com/storage/modules/90/0-PT-Process.png)

### Pre-Engagement

- Educate the client and adjust the contract (everything is strictly recorded).
- Other arrangements are made such as:
    - Non-Disclosure Agreement
    - Goals
    - Scope
    - Time Estimation
    - Rules of Engagement

### Information Gathering

- Obtain important information about the various assets.
- Information about software, hardware and the company itself are usually gathered.
- This information will be used to gain the initial foothold.

### Vulnerability Assessment

- Here, the results gathered in info gathering are used to suss out vulnerabilities in the system.
- This can be done both manually and automatically.
- Determines threat level and susceptibility of a company to cyber attacks.

### Exploitation

- Just exploit what you found before.

### Post-Exploitation

- We may try to persist our access to the exploited machine
- We may also try to gain elevated privileges.
- We might also perform this to demonstrate the impact of the access.

### Lateral Movement

- Movement within the network to access hosts at same or higher level.
- Many techniques are used based on information found on the host.

### Proof of Concept

- Document a step-by-step process of how we did what we did.
- Goal is to paint a picture of how we chained multiple misconfigurations to gain acess.

### Post Engagement

- Documentation is prepped for both client and admins to figure out the severities of the exploit.
- Here the deliverables are created for the client.
- These are archived as per contractual obligations.

### Importance

| Stage               | Description |
|---------------------|-------------|
| **1. Pre-Engagement** | The first step is to create all the necessary documents in the pre-engagement phase, discuss the assessment objectives, and clarify any questions. |
| **2. Information Gathering** | Once the pre-engagement activities are complete, we investigate the company's existing website we have been assigned to assess. We identify the technologies in use and learn how the web application functions. |
| **3. Vulnerability Assessment** | With this information, we can look for known vulnerabilities and investigate questionable features that may allow for unintended actions. |
| **4. Exploitation** | Once we have found potential vulnerabilities, we prepare our exploit code, tools, and environment and test the webserver for these potential vulnerabilities. |
| **5. Post-Exploitation** | Once we have successfully exploited the target, we jump into information gathering and examine the webserver from the inside. If we find sensitive information during this stage, we try to escalate our privileges (depending on the system and configurations). |
| **6. Lateral Movement** | If other servers and hosts in the internal network are in scope, we then try to move through the network and access other hosts and servers using the information we have gathered. |
| **7. Proof-of-Concept** | We create a proof-of-concept that proves that these vulnerabilities exist and potentially even automate the individual steps that trigger these vulnerabilities. |
| **8. Post-Engagement** | Finally, the documentation is completed and presented to our client as a formal report deliverable. Afterward, we may hold a report walkthrough meeting to clarify anything about our testing or results and provide any needed support to personnel tasked with remediating our findings. |


## Pre Engagement: In-Depth

- It is the stage of prep for the actual pentest.
- Three Essential Components:
1. Scoping questionnaire
2. Pre-Engagement meeting
3. Kick-Off meeting

An NDA is signed by all parties involved with the pentest process.

### Documents to be created

| S.No | Document                                            | Timing for Creation                      |
|------|-----------------------------------------------------|------------------------------------------|
| 1    | Non-Disclosure Agreement (NDA)                      | After Initial Contact                    |
| 2    | Scoping Questionnaire                               | Before the Pre-Engagement Meeting        |
| 3    | Scoping Document                                    | During the Pre-Engagement Meeting        |
| 4    | Penetration Testing Proposal (Contract/Scope of Work - SoW) | During the Pre-Engagement Meeting |
| 5    | Rules of Engagement (RoE)                           | Before the Kick-Off Meeting              |
| 6    | Contractors Agreement (Physical Assessments)        | Before the Kick-Off Meeting              |
| 7    | Reports                                              | During and after the conducted Penetration Test |

### Scoping Questionnaire

- Better understand the service expectations from the client.
- Also ask about information disclosure and evasiveness.

Helps us assign the right resources and deliver the engagement based on the expectations.

### Pre-Engagement meeting

- discusses all relevant and essential components with the customer before the penetration test
- information gathered during this phase, along with the data collected from the scoping questionnaire, will serve as inputs to the Penetration Testing Proposal

#### Contract Checklist

| Checkpoint                  | Description |
|----------------------------|-------------|
| - [ ] **NDA**              | Non-Disclosure Agreement (NDA) refers to a secrecy contract between the client and the contractor regarding all written or verbal information concerning an order/project. The contractor agrees to treat all confidential information brought to its attention as strictly confidential, even after the order/project is completed. Furthermore, any exceptions to confidentiality, the transferability of rights and obligations, and contractual penalties shall be stipulated in the agreement. The NDA should be signed before the kick-off meeting or at the latest during the meeting before any information is discussed in detail. |
| - [ ] **Goals**            | Goals are milestones that must be achieved during the order/project. In this process, goal setting is started with the significant goals and continued with fine-grained and small ones. |
| - [ ] **Scope**            | The individual components to be tested are discussed and defined. These may include domains, IP ranges, individual hosts, specific accounts, security systems, etc. Our customers may expect us to find out one or the other point by ourselves. However, the legal basis for testing the individual components has the highest priority here. |
| - [ ] **Penetration Testing Type** | When choosing the type of penetration test, we present the individual options and explain the advantages and disadvantages. Since we already know the goals and scope of our customers, we can and should also make a recommendation on what we advise and justify our recommendation accordingly. Which type is used in the end is the client's decision. |
| - [ ] **Methodologies**    | Examples: OSSTMM, OWASP, automated and manual unauthenticated analysis of the internal and external network components, vulnerability assessments of network components and web applications, vulnerability threat vectorization, verification and exploitation, and exploit development to facilitate evasion techniques. |
| - [ ] **Penetration Testing Locations** | External: Remote (via secure VPN) and/or Internal: Internal or Remote (via secure VPN) |
| - [ ] **Time Estimation**  | For the time estimation, we need the start and end dates for the penetration test. This provides a precise time window to perform the test and helps us plan our procedure. It is also vital to explicitly determine the duration of the time windows for each phase of the attack, such as Exploitation, Post-Exploitation, and Lateral Movement. These can be carried out during or outside regular working hours. When testing outside regular working hours, the focus is more on the security solutions and systems that should withstand our attacks. |
| - [ ] **Third Parties**    | For the third parties, it must be determined via which third-party providers our customer obtains services. These can be cloud providers, ISPs, and other hosting providers. Our client must obtain written consent from these providers describing that they agree and are aware that certain parts of their service will be subject to a simulated hacking attack. It is also highly advisable to require the contractor to forward the third-party permission sent to us so that we have actual confirmation that this permission has indeed been obtained. |
| - [ ] **Evasive Testing**  | Evasive testing is the test of evading and passing security traffic and security systems in the customer's infrastructure. We look for techniques that allow us to find out information about the internal components and attack them. It depends on whether our contractor wants us to use such techniques or not. |
| - [ ] **Risks**            | We must also inform our client about the risks involved in the tests and the possible consequences. Based on the risks and their potential severity, we can then set the limitations together and take certain precautions. |
| - [ ] **Scope Limitations & Restrictions** | It is also essential to determine which servers, workstations, or other network components are essential for the client's proper functioning and its customers. We will have to avoid these and must not influence them any further, as this could lead to critical technical errors that could also affect our client's customers in production. |
| - [ ] **Information Handling** | HIPAA, PCI, HITRUST, FISMA/NIST, etc. |
| - [ ] **Contact Information** | For the contact information, we need to create a list of each person's name, title, job title, e-mail address, phone number, office phone number, and an escalation priority order. |
| - [ ] **Lines of Communication** | It should also be documented which communication channels are used to exchange information between the customer and us. This may involve e-mail correspondence, telephone calls, or personal meetings. |
| - [ ] **Reporting**        | Apart from the report's structure, any customer-specific requirements the report should contain are also discussed. In addition, we clarify how the reporting is to take place and whether a presentation of the results is desired. |
| - [ ] **Payment Terms**    | Finally, prices and the terms of payment are explained. |

#### Rules of Engagement checklist

| Checkpoint                         | Contents |
|-----------------------------------|----------|
| - [ ] **Introduction**            | Description of this document. |
| - [ ] **Contractor**              | Company name, contractor full name, job title. |
| - [ ] **Penetration Testers**     | Company name, pentesters full name. |
| - [ ] **Contact Information**     | Mailing addresses, e-mail addresses, and phone numbers of all client parties and penetration testers. |
| - [ ] **Purpose**                 | Description of the purpose for the conducted penetration test. |
| - [ ] **Goals**                   | Description of the goals that should be achieved with the penetration test. |
| - [ ] **Scope**                   | All IPs, domain names, URLs, or CIDR ranges. |
| - [ ] **Lines of Communication**  | Online conferences or phone calls or face-to-face meetings, or via e-mail. |
| - [ ] **Time Estimation**         | Start and end dates. |
| - [ ] **Time of the Day to Test** | Times of the day to test. |
| - [ ] **Penetration Testing Type**| External/Internal Penetration Test/Vulnerability Assessments/Social Engineering. |
| - [ ] **Penetration Testing Locations** | Description of how the connection to the client network is established. |
| - [ ] **Methodologies**           | OSSTMM, PTES, OWASP, and others. |
| - [ ] **Objectives / Flags**      | Users, specific files, specific information, and others. |
| - [ ] **Evidence Handling**       | Encryption, secure protocols |
| - [ ] **System Backups**          | Configuration files, databases, and others. |
| - [ ] **Information Handling**    | Strong data encryption |
| - [ ] **Incident Handling and Reporting** | Cases for contact, pentest interruptions, type of reports |
| - [ ] **Status Meetings**         | Frequency of meetings, dates, times, included parties |
| - [ ] **Reporting**               | Type, target readers, focus |
| - [ ] **Retesting**               | Start and end dates |
| - [ ] **Disclaimers and Limitation of Liability** | System damage, data loss |
| - [ ] **Permission to Test**      | Signed contract, contractors agreement |

### Kick-Off meeting

- occurs at a scheduled time, in-person
- nature of the penetration test and how it will take place
- inform customers about potential risks during a penetration test

### Contractors Agreement

- If the penetration test also includes physical testing, then an additional contractor's agreement is required

#### Contractors Agreement Checklist

- [ ] **Introduction**
- [ ] **Contractor**
- [ ] **Purpose**
- [ ] **Goal**
- [ ] **Penetration Testers**
- [ ] **Contact Information**
- [ ] **Physical Addresses**
- [ ] **Building Name**
- [ ] **Floors**
- [ ] **Physical Room Identifications**
- [ ] **Physical Components**
- [ ] **Timeline**
- [ ] **Notarization**
- [ ] **Permission to Test**

### Question

How many docs are required to conduct a pentest?
Ans: 7


## Information Gathering In-Depth

Usually done via:
- OSINT
- Infrastructure enumeration
- Service Enumeration
- Host Enumeration

### Open Source Intelligence

- Basically information publicly available on the internet.
- Companies can unintentionally expose sensitive information on public forums.
- It is possible to find highly sensitive information such as passwords, hashes, keys, tokens, and much more that can give us access to the network within just a few minutes.
- Often, company repositories on GitHub often expose secrets, stuff like hashes, ssh keys, tokens, passwords, etc. This can be crucial to gaining initial access to a company resource.

![Image Didn't Load](https://academy.hackthebox.com/storage/modules/90/searchcode3.png)

### Infrastructure Enumeration

- Try to overview the company position on the internet and intranet (including ip addresses, nameservers, mail servers, cloud instances, etc).
- We use OSINT and active scans.
- We also determine the company security measures. The precision of this test determines how easily we can disguise our attacks (Evasive testing).
- Also gives an idea what sort of techniques could trigger the firewall.

### Service Enumeration

- Essentially, we just obtain the service versions, their version history, what information it provides us and the reason it can be used.
- This allows us to gain certain options to attack the system. Admins are usually afraid to update software as it might break the system it is implemented in.

### Host Enumeration

- Can be done via OSINT or active scans
- It allows us to figure out the service versions, OS version, etc.
- Doesnt matter if this part is external or internal.
- During this process, we determine what role the host plays and which ports it uses for this purpose.
- Internal host enumeration may occur **after** successful exploitation of a target, where we look for sensitive files, local services, scripts, applications, information, and other things that could be stored on the host.

### Pillaging

- This is basically like loot in a game after completing a mission.
- All you do is take all the information you can (this can include ensitive information locally on the already exploited host, such as employee names, customer data, and much more).
- This part only happens **after exploiting** the target host.
- The main role this plays is to demonstrate the impact of an attack. This can go in the report.


## Vulnerability Assessment In-Depth

- Examine and analyze the information gathered during info gathering to make conclusions.

### Types of analysis

| **Analysis Type** | **Description** |
|-------------------|-----------------|
| **Descriptive**   | Descriptive analysis is essential in any data analysis. On the one hand, it describes a data set based on individual characteristics. It helps to detect possible errors in data collection or outliers in the data set. |
| **Diagnostic**    | Diagnostic analysis clarifies conditions' causes, effects, and interactions. Doing so provides insights that are obtained through correlations and interpretation. We must take a backward-looking view, similar to descriptive analysis, with the subtle difference that we try to find reasons for events and developments. |
| **Predictive**    | By evaluating historical and current data, predictive analysis creates a predictive model for future probabilities. Based on the results of descriptive and diagnostic analyses, this method of data analysis makes it possible to identify trends, detect deviations from expected values at an early stage, and predict future occurrences as accurately as possible. |
| **Prescriptive**  | Prescriptive analytics aims to narrow down what actions to take to eliminate or prevent a future problem or trigger a specific activity or process. |

### Vulnerability Research and Analysis

- IG and VR can be considered descriptive analysis.
- Vulnerability Research: Look for known vulnerabilities, exploits, and security holes that have already been discovered and reported.
- We can look in places like: CVEdetails, Exploit DB, Vulners, Packet Storm Security, NIST
- From this we can pinpoint the exact weakness of the system causing the vulnerability and use a PoC to exploit it. Ofentimes, this PoC must be customized for the specific use case.

### Assessment of Possible Attack Vectors

- Includes actual testing.
- Analyze historical information and combine it with the current information that we have been able to find out.
- Whether we have received specific evasion level requirements from our client, we test the services and applications found locally or on the target system.
- We replicate the target system locally by using the information obtained during the IG phase.

### The Return

- If we are unable to detect any vulnerabilities in the system, we go back to IG and start going more in-depth. This often overlaps with the VA phase and there should be a regular back and forth.
- A pentest is not the same as a CTF, where in a CTF the goal is to gain the highest access in the shortest time, in a pentest we want to ensure quality, find every hole and detect it.
- It would be pretty stupid if a hacker got access through a simple vector that we should have discovered :).

NOTE: **A real pentest is not a CTF**

### Question

What type of analysis can be used to predict future probabilities?

Ans: predictive

## Exploitation In-Depth

- Weankesses found during enumeration are exploited in this phase. 

### Prioritization of Possible Attacks

- Prioritizing your attacks should be based on what you found during VA phase.
- Usually these factors considered:
    - Probability of success (CVSS scoring can help)
    - Complexity
    - Probability of damage

### Preparation for the Attack

- Sometimes good PoC can't be found. So we try and build the exploit using the instructions in the CVE on a local instance of the target environment.
- Always check with the client before running an exploit, if in doubt. Give all the possible details to get the best guidance.
- After gaining initial access we move to Post-Exploitation.

## Post Exploitation In-Depth

- Aims to gather sensitive information which requires higher privilege than a standard user.

### Evasive Testing

- If a skilled admin is monitoring a network that you just penetrated, chances are you won't make it very far.
- Even if we're detected, we can still provide value to a client by writing up our entire attack chain, study why we were detected and work on improving our own evasion skills.

### Information Gathering

- Enumerate the system since we have higher level access now.
- This can expose more attack surfaces and more vectors. This is called pillaging.

### Pillaging

- Understand the role of the host in the corporate network.
- We analyze stuff like Interfaces, Routing, DNS, ARP, Services, VPN, IP Subnets, Shares, Network Traffic.
- We will also hunt for sensitive data such as passwords on shares, local machines, in scripts, configuration files, password vaults, documents (Excel, Word, .txt files, etc.), and even email.

### Persistence

- The act of maintaining access to the exploited host.
- The sequences are non-standardized because each system is unique.
- This is usually done as soon as access is gained to a system so that we don't have to attack it over and over.

### Vulnerability Assessment

- This is the same as before but now we look from the perspective of an inside user.

### Privilege Escalation

- The act of escalating our privileges to the highest possible in a domain. 
- Doesn't always have to happen locally on the system. We might sometimes obtain credentials or other access methods from other systems, that allow us to gain the full ownership of the target system.

### Data Exfiltration

- See module (this is all standard known stuff)

### Questions

1. How many types of Evasive testing are mentioned in this section?

Ans: 3

2. What is the name of the security standard for credit card payments that a company must adhere to? (Answer Format: acronym)

Ans: PCI-DSS


## Lateral Movement

- Goal is to test everything that we could do inside the exploited network.

### Pivoting

- Techniques which allow us to use the exploited system/host as a proxy to run scans.
- We try to pivot to a user with higher privileges.

### Evasive Testing

- Hiding our actions so as to not alert the blue team.

### Information Gathering

- We must first get an overview of which systems and how many can be reached from our system.

### Vulnerability Assessment

- From inside a network this usually differs since there are far more errors inside the network than the outside.
- Groups and the rights they are assigned play an important role.

### Privilege Exploitation

- We can use the access control misconfigurations we discover in the previous step to exploit and gain higher access.

### Post-Exploitation

- We again collect system information, data from created users, and business information that can be presented as evidence. However, we must again consider how this different information must be handled and the rules defined around sensitive data in the contract.


## Proof of Concept In-Depth

- Essentially serves as proof that a project is feasible in principle
- A significant disadvantage of this is that admins and devs "fight" against the PoC.
- For example, say that a password `password123` was found and exploited. The issue becomes that the devs won't recognize the fact that the `password policy` is the issue and that the password is a part of the issue. So communication must be clear in this regard. Similarly, devs may patch the exploit, but not the root cause of the exploit.


## Post-Engagement In-Depth

- Cleanup: Delete and remove scripts, exploits or configuration changes we've made to a system during our engagement.
- Documentation and Reporting: Must have adequate documentation of all our findings. We must mainly have the following
    - An attack chain (in the event of full internal compromise or external to internal access) detailing steps taken to achieve compromise
    - A strong executive summary that a non-technical audience can understand
    - Detailed findings specific to the client's environment that include a risk rating, finding impact, remediation recommendations, and high-quality external references related to the issue
    - Adequate steps to reproduce each finding so the team responsible for remediation can understand and test the issue while putting fixes in place
    - Near, medium, and long-term recommendations specific to the environment
    - Appendices which include information such as the target scope, OSINT data (if relevant to the engagement), password cracking analysis (if relevant), discovered ports/services, compromised hosts, compromised accounts, files transferred to client-owned systems, any account creation/system modifications, an Active Directory security analysis (if relevant), relevant scan data/supplementary documentation, and any other information necessary to explain a specific finding or recommendation further

- Report Review Meeting: A report review meeting is customary to talk about all the findings and interpretations made from the report.
- Deliverable Acceptance: The scope must clearly define the acceptance of project deliverables.
- Post-Remediation Testing: We show evidence of the remediation done to the findings.

