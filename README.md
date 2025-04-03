# Stark Medical Security System Documentation

**Author:** Onyinyechukwu Uge  
**Project Title:** *Secure HealthCare Information System for Stark Medical*

## Origin

Stark Medical is a newly established healthcare organization in the heart of Winnipeg, driven by a bold mission to deliver accessible, high-quality healthcare to the community. While its ambition and resources are not in question—possessing all the tools necessary to serve patients effectively—the organization has recently faced critical challenges related to information security.

Surprisingly, these security vulnerabilities were not the result of financial limitations but rather a lack of due attention to the importance of having a robust, secure system to manage the institution’s daily operations. This oversight has now brought the risks into sharp focus.

## Incident

Just last month, Stark Medical experienced a significant cybersecurity breach involving a masquerade attack. An unauthorized individual was able to exploit vulnerabilities in the system and gain access to the previous server. During this window, the attacker issued several unauthorized requests and accessed sensitive medical records before being detected.

Unfortunately, by the time the breach was discovered, critical role-restricted information had already been compromised. These events reveal a fundamental disregard for core cybersecurity principles and clearly fall short of compliance with HIPAA regulations.

## Project Motivation

As an aspiring cybersecurity systems analyst, I was inspired to create a system that not only responds to this incident but also lays the groundwork for a secure, future-proof platform. The system outlined in this documentation serves as a blueprint—designed to evolve into a comprehensive security framework for Stark Medical. The goals set out include:

- **Role-Based Access Control (RBAC):** To limit access strictly based on predefined user roles, ensuring sensitive data is only available to authorized personnel.
- **Threat Mitigation:** Protection against common attack vectors such as SQL Injection, Cross-Site Scripting (XSS), Man-in-the-Middle (MITM) attacks, etc.
- **Secure Request Validation:** Server requests are verified using trusted IPs or session validation, especially important for remote employees.
- **Intrusion Prevention:** Rate limiting and fail-safe protocols to counter Denial-of-Service (DoS) attacks while maintaining availability.
- **Multi-Factor Authentication (MFA):** Adds a second layer of identity verification at login.
- **Encryption:** Secures data both at rest and in transit using unique keys and non-repudiation mechanisms.

---

## 1. Access Control and Authentication

### Multi-Factor Authentication (MFA)
- Enforced for all user roles using Time-Based One-Time Passwords (TOTP).
- Setup and verification handled via `setupMfa.njk`, `setupVerifyMfa.njk`, and `loginVerifyMfa.njk`.
- Rate limiting (3 attempts/hour) implemented to prevent brute force attacks.

### Session Management
- Sessions are protected with `httpOnly`, `secure`, and `sameSite` cookie flags.
- Automatic session expiration after 30 minutes of inactivity (`rolling: true`).

### Password Policy and History
- Passwords are securely hashed using bcrypt.
- Users are required to change passwords upon initial login.
- Password history feature prevents reuse of the last 5 passwords (currently in progress).

---

## 2. HIPAA Compliance

### Privacy Rule
- Access to patient records is restricted by role.
- Protected Health Information (PHI) is only visible to assigned doctors and assistants.
- No exposure of PHI in public or unauthorized contexts.

### Security Rule
- Field-level encryption applied to sensitive data in MongoDB (e.g., address, license number).
- SSL certificates enforce HTTPS for all data in transit.
- Express Helmet integrated to set strict HTTP headers and prevent common attacks.

### Audit Controls
- A dedicated logging system (`Logger.js`) tracks user authentication, session activity, and database access.
- Session-linked logs ensure non-repudiation of critical actions.

---

## 3. Data Integrity and Confidentiality

### Encryption
- HTTPS enforced via TLS encryption.
- MongoDB field-level encryption for sensitive attributes.

### Mongo Sanitize
- Prevents NoSQL injection attacks by sanitizing user inputs.

### Helmet
- Mitigates widespread web vulnerabilities via secure HTTP headers.

### Role-Based Access Control (RBAC)
- User interfaces and routes are tailored by role (e.g., doctor, assistant, pharmacist).
- Role-based route protection enforced through `ensureAuthenticated()` middleware.

---

## 4. Threat Mitigation Strategy

### Eavesdropping
- HTTPS ensures encrypted traffic, preventing data leakage during transmission.
- Sensitive data never passed in plain text or URL parameters.

### Dictionary & Brute Force Attacks
- Strong password hashing with bcrypt.
- Login and MFA verification endpoints protected by rate limiting and IP/session lockouts.

### Malware and Ransomware
- Input sanitization and strict validation (file and form-based) planned for next release.
- Database backup to secure offsite locations is in progress.

### Intrusion and Anomaly Detection
- Future plans include integrating anomaly detection (e.g., login from unusual IP addresses).
  - MongoDB already addresses this, but more testing will be conducted to ensure consistency in authorisation.
- User and database activity logs already operational.
- Plans to connect with SIEM tools or lightweight intrusion detection systems.

### Denial-of-Service (DoS) Attacks
- Express rate limiters guard critical endpoints like login and MFA.
- Secure response headers provided through Helmet.

---

## 5. Compliance and Future Enhancements

### Current Compliance
- System adheres to HIPAA Privacy and Security Rules.
- Follows cybersecurity best practices laid out by NIST.

### Next Steps (Security Implementations)
- Conduct penetration testing and vulnerability scans.
- Enable automated backups and disaster recovery plans.
- Set up real-time alerts for suspicious behavior.
- Launch user education modules including in-app security guides and tips.

### Next Steps (Non-Security Implementations)
- Add a websocket function to ensure communication between different authorised users. A means for effective organisation between employees that work on sight, and possibly from home.
- Adding patients to the database and storing their information with strict compliance to HIPAA security regulations.
- Ability to schedule, change, and cancel appointments with immediate email confirmations.

---

## Summary

The system implemented at Stark Medical reflects a commitment to layered security—where authentication, encryption, access control, and monitoring work together to safeguard healthcare data. By embedding HIPAA compliance and best cybersecurity practices into the system architecture, we’ve made substantial progress in addressing the vulnerabilities previously faced.

While this is a foundational phase, the platform now has strong protections in place and a clear roadmap for becoming a fully resilient and secure health information system—one that serves both patients and practitioners with confidence.