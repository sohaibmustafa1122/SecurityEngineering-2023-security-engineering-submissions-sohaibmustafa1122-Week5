# SecurityEngineering-2023-security-engineering-submissions-sohaibmustafa1122-Week5
#Week 5


###Task 1: Bring your own devices

1. Intrusive Application Practices
These include such applications that gather more app data than necessary, track users’ activities without authorization or engage in other actions that were not previously explained by the applications. Such applications create privacy issues and may result in violation of privacy by accessing private information. Such practices have to be identified by organizations that have to scrutinize and regulate applications.

2. Identity theft through phishing
Phishing scams deceive people into sharing their log-in information with the fake service. In a BYOD environment, users are likely to be trapped in phishing, which results in unauthorized access to both personal and business information. This can be avoided through proper anti-phishing measures and regular training to the employee’s on proper handling of emails.

3. Outdated Phones
Carrying tech devices that are no longer supported by the manufacturer through regular updates means that they contain open securities. Such devices are not updated frequently which implies that they can contain a malware and can be easily exploited. Updating the program on a regular basis, and enhancing the compliances of the devices used are crucial in implementing an organization security.

4. Sensitive Data Transmissions
Data that is considered to be sensitive may be communicated through channels that are not encrypted and therefore can be intercepted. It is important to always encrypt any data that is in transit and in particular if one is transacting in an open WAP.

5. Brute Force Attacks to Unlock a Phone
A passcode attack is a process of entering the correct passcode, which can be done through trial and error. Inadequate or basic passwords allow the attackers to easily penetrate a device. It is equally important to enforce password and use measures as well as to lock the devices in case of many wrong attempts.

6. Application Credential Storage Vulnerability
Keeping credential within applications without adequate security leads to credential compromise. Cyber criminals can acquire login information from applications that for have inadequate security measures. The following are some of the preventive measures which can eliminate such vulnerabilities; ensuring that the application stores the credential securely, and ensuring that the data is encrypted.

7. Unmanaged Device Protection
The devices that do not have proper security management are a threat to the organization’s network. Unmanaged devices may not follow the security controls hence leading to unauthorized access. The use of device management solutions guarantees that all the devices are secure before being allowed to connect to the company’s resources.

8. Protection of Lost or Stolen Data
In the case where a device is lost or stolen, unauthorized persons will be able to access information on the device. Use of mechanisms such as remote wipe and encryption of data that is stored is essential in preventing the theft of such data.

9. Preventing Enterprise Data from Being Accidentally Copied to a Cloud Service
By default, users sync their data with corporate cloud storage solutions by entering their corporate login details into personal cloud accounts, making the information publicly accessible to some individuals. They ensure devices are set up in a way to keep work related data from being backed up to unmanaged cloud services to maintain data security.

###Task 2: attacks on CPU execution

1. Spectre-PHT-CA-OP (Cross-Address-space Out of Place)
This variant of Spectre aims at the CPU’s branch prediction element especially the Pattern History Table. It forces the CPU to execute instructions that should not be executed, and enables the attacker to view cached data from a victim’s address space. Through branch misprediction, the attack makes the information, for instance, cryptographic key or password in an exposed state. Based on the nature depicting Spectre-PHT-CA-OP as the attack that focuses on the speculative executions of the code on the Intel CPUs and possibly on others. Mitigation includes both hardware patches and software fixes like Retpoline or timer reduction techniques but they have an effect on performance.

2. Meltdown
Meltdown utilizes out-of-order execution they both increase CPU performance by enabling a number of instructions to be processed ahead of time. In Meltdown, attackers take advantage of this by initiating a faulting instruction, which under normal circumstances should lead to discarding of data. However, Meltdown makes sure that this data is stored in the cache, and the attackers can read the unauthorized memory, including the kernel space. Intel and some ARM CPUs are especially susceptible. In order to contain Meltdown, developers have implemented Kernel Page-Table Isolation ( KPTI) system in which kernel memory is shielded from the user space to avoid information tampering. However, the performance cost of these mitigations can be quite steep.

3. Retbleed
Retbleed was disclosed in 2022 and attacks CPUs’ speculative execution to aim at return stack buffers (RSB). This attack tricks the CPU into predicting wrong return addresses, and thus running of sensitive code from undesired locations. Retbleed impacts Intel’s 6th to 8th generation Core processors and AMD’s Zen 1 and Zen 2 chip designs. The methods for patching Retbleed, are microcode updates, along with applying retpoline (return trampoline) software fix that slows down instructions by 39% on Intel and 14% on AMD.

In comparing these attacks, Spectre focuses on branch misprediction, Meltdown on out-of-order execution, and Retbleed on return address prediction. They all exploit speculative execution to leak sensitive data, yet each targets different CPU functionalities. Mitigations involve combinations of hardware patches and software defenses, often leading to performance trade-offs.

##References:

1. Stanford University (2024). Modern Cryptography: Theory and Applications.
2. Virsec (2024). Spectre and Meltdown Attacks.
3. ArXiv (2024). A Systematic Evaluation of Transient Execution Attacks and Defenses.



###Task3: Securing OS

##Operating System Vulnerabilities and Mitigations
Malware and Viruses can interfere with systems and corrupt files, steal data or in some case render the device unusable through ransomware. For instance Windows guards against these dangers through Windows Defender for scheduled scans and regular updates and also with the help of other security software’s like McAfee or Norton. 
Malware Activation through software vulnerabilities is the act by the attackers to utilize the open holes in the operating system or applications to execute unauthorized code. Linux systems can avoid this through SELinux or AppArmor, where abilities are limited for an application and constant updates on vulnerabilities exist. 
Phishing and Social Engineering attacks force the user to disclose his/her password. Mac fights phishing with features such as Mail Privacy Protection and insists on updating its operating system for better protection. Other risks can also be mitigated by tools such as 1Password. 
Drive-by Downloads are a type of infection that happens when a visitor downloads malware to his or her computer without consent while browsing a site. Windows offsets this through its SmartScreen filter that identifies and avoids websites or downloads that appear suspicious and because browser add-ons such as ad blockers can help foil such attacks. 
Zero- Day Exploits involves protection of openings that are unaddressed by developers, an area in which intruders are allowed or data is compromised. And on this front, Linux systems are well equipped with deploying faster security patches and using a firewall for further security measures like UFW. USB/Removable Media Attacks can infect a computer through infected USB or any other removable media storage. 
To this risk, Mac uses Gatekeeper to prevent unauthorized applications and disables installation and run automatically from external devices. Password Cracking techniques enable the attacker to guess or decrypt the password of an account. 
Windows does this through password complexity, use of Windows Hello for fingerprints, facial recognition and iris scans and built-in encryption Windows BitLocker. In each case, operating systems enlist local tools as well as third-party security software to counter all these threats.


###Task4: Logging

###Operating System Log Files: Information, Storage, and Threat Detection

#Application Logs

Information: Application logs record events from applications, such as errors, warnings, and runtime behavior. These logs help identify how an application is performing, tracking issues like crashes or failed operations.

Storage:
Windows: Found in the Event Viewer under "Applications and Services Logs".

Mac: Located in /Library/Logs/ and accessible via the Console app.

Linux: Stored in /var/log/ (e.g., /var/log/syslog for general logs).

Threats: Monitoring application logs can reveal unauthorized access attempts or unusual patterns, such as repeated failed login attempts, indicating brute-force attacks or other security threats.

Monitoring: Tools like Splunk or native OS log viewers like Event Viewer (Windows) or syslog (Linux) are useful for monitoring.

##Event Logs

Information: Event logs capture system-wide activities, such as user logins, device connections, and system shutdowns. These logs help trace user behavior and monitor for anomalies.

Storage:
Windows: Managed through the Event Viewer, found under "Windows Logs" (Security, System).

Mac: Managed via the Console app in /var/log/system.log.

Linux: Typically stored in /var/log/auth.log or /var/log/messages.

Threats: Event logs can reveal suspicious user activity, like failed login attempts or unexpected privilege escalations, which may signal potential hacking attempts.

Monitoring: Continuous monitoring using SIEM (Security Information and Event Management) tools like ManageEngine or native OS tools can identify abnormal activity early.

##Service Logs

Information: These logs capture detailed information about the services running on an OS, including start/stop events and performance data.

Storage:
Windows: Viewable in the Event Viewer under "Windows Logs" or specific service logs.

Mac: Located in /var/log/ and managed via the Console.

Linux: Found in /var/log/ (e.g., /var/log/daemon.log).

Threats: Monitoring service logs can detect potential Denial of Service (DoS) attacks or unauthorized service use.

Monitoring: External tools like ELK Stack (ElasticSearch, Logstash, Kibana) can aggregate and visualize service logs.

##System Logs

Information: System logs record core OS-level events, including hardware changes, system startup, and shutdown processes.

Storage:
Windows: Event Viewer, found under "System".

Mac: Managed via the Console in /var/log/system.log.

Linux: Typically located in /var/log/syslog or /var/log/messages.

Threats: System logs can expose hardware failures, unauthorized shutdowns, or unexpected reboots, which may be signs of malware or system tampering.

Monitoring: Automated monitoring with tools like Splunk or Graylog can help maintain system integrity by flagging abnormal events.

Monitoring on Personal Systems

Monitoring logs on personal computers can be done using built-in tools like Windows Event Viewer, macOS Console, and Linux syslog utilities. For more advanced monitoring, SIEM solutions like Splunk or ManageEngine can aggregate and analyze logs, alerting you to potential threats in real time.

#Sources:

1. Splunk (2024). Log Files: Definition & Introduction​. [Splunk](https://www.splunk.com/en_us/blog/learn/log-files.html)

2. ManageEngine (2024). SIEM Log Types and Why They Matter​ [MANAGEENGINE](https://www.manageengine.com/log-management/siem/collecting-and-analysing-different-log-types.html).

3. Logz.io (2024). Security Analytics: Essential Logs to Monitor​ [LOGZ.IO](https://logz.io/blog/logs-to-monitor-for-security-analytics/).

