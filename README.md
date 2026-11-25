# SecureVault QR – Secure Document Storage and QR Code Access System

> **A production-grade, full-stack, responsive web application** designed to store confidential documents with **AES-256-GCM Envelope Encryption**, generate **dynamic high-resolution QR codes**, and grant access through **4-character passwords** verified with **Argon2id**.

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [Technology Stack](#technology-stack)
3. [Architecture & System Flow](#architecture--system-flow)
4. [Cybersecurity & Cryptographic Architecture](#cybersecurity--cryptographic-architecture)
5. [The 4-Character Password Security Analysis](#the-4-character-password-security-analysis)
6. [Database Schema & PostgreSQL Integration](#database-schema--postgresql-integration)
7. [Development Stages (1 Through 12 Explained)](#development-stages-explained)
8. [Quick Start & How to Run](#quick-start--how-to-run)
9. [Automated Test Suite & Verification](#automated-test-suite--verification)
10. [REST API Documentation](#rest-api-documentation)

---

## 1. Project Overview

**SecureVault QR** solves the challenge of distributing sensitive, confidential documents without exposing direct storage URLs or relying on unencrypted email attachments. 

### Core Capabilities:
1. **User Authentication**: Secure user registration and login powered by Argon2id password hashing and signed HTTP-only JWT sessions.
2. **Encrypted Document Vault**: Upload PDF, Office documents (DOCX, PPTX, XLSX), images (PNG, JPG), and text files. All files are encrypted in-memory using **AES-256-GCM Envelope Encryption** before being written to private disk storage.
3. **Dynamic QR Code Generation**: An unpredictable 256-bit cryptographically secure random access token is generated for every document. Only the salted SHA-256 hash of this token is saved in the database.
4. **4-Character PIN System**: Every document receives a unique 4-character password (e.g. `A7#k`) using an unambiguous character set. The password hash is stored using **Argon2id** (memory-hard algorithm).
5. **Mobile-First Public Scan & Access Flow**: When a recipient scans the QR code with their smartphone camera, they are prompted to enter the 4-character password in a clean mobile UI.
6. **Brute Force Defense**: Strict server-side rate limiting locks out access for 15 minutes after 5 consecutive failed attempts.
7. **On-the-Fly Decryption**: Authorized recipients receive a short-lived (15-minute) signed access session. The document is decrypted and streamed in-memory with correct MIME headers; unencrypted files are never saved to disk.
8. **Owner Lifecycle Controls**: Document owners can regenerate QR codes (permanently invalidating previous QR codes), update passwords, set expiration dates, view access logs, or permanently delete documents.

---

## 2. Technology Stack

| Layer | Technologies Used | Purpose |
|---|---|---|
| **Frontend** | React 18, TypeScript, Tailwind CSS, Lucide React, Vite 5 | Responsive SaaS interface, 4-char PIN slots, real-time feedback, mobile-friendly camera access flow. |
| **Backend** | Node.js (LTS), Express 5, Multer, Helmet, CORS, Cookie-Parser | REST API, in-memory stream processing, security headers, rate limiting. |
| **Cryptography** | Node Crypto (`crypto`), `@node-rs/argon2` | AES-256-GCM Envelope Encryption, 12-byte IVs, 16-byte Auth Tags, Argon2id password hashing. |
| **QR Engine** | `qrcode` | Vector and high-resolution PNG generation, direct binary buffer downloads. |
| **Database** | PostgreSQL (`pg`), Universal Fallback Adapter | Relational tables, foreign keys, indexes, with zero-friction local persistent fallback (`storage/database.json`). |
| **Storage** | Private Local Vault (`backend/storage/vault`) | Private encrypted object storage, modular for Amazon S3 / Google Cloud Storage. |

---

## 3. Architecture & System Flow

```
[User / Owner]                          [Backend API]                    [Encrypted Vault & DB]
      |                                       |                                     |
      |-- 1. Upload File (PDF/IMG/DOC) ------>|                                     |
      |                                       |-- 2. Generate Data Key (DEK) ------>|
      |                                       |-- 3. AES-256-GCM Encrypt File ----->| Save <UUID>.enc
      |                                       |-- 4. Encrypt DEK with Master Key -->|
      |                                       |-- 5. Generate 4-Char PIN ---------->| Argon2id Hash
      |                                       |-- 6. Generate 32-Byte QR Token ---->| SHA-256 Hash
      |<-- 7. Return QR Code + PIN -----------|                                     |
      |                                       |                                     |
[Recipient / Mobile]                          |                                     |
      |                                       |                                     |
      |-- 8. Scan QR Code ------------------->|-- Validate Token Hash ------------->|
      |<-- 9. Display PIN Entry Screen -------|                                     |
      |-- 10. Enter 4-Char Password --------->|-- Verify Argon2id (Max 5 tries) --->|
      |                                       |-- (If Success) 15-min Session ------>|
      |<-- 11. Decrypt & Stream File ---------|-- Decrypt AES-256-GCM on-the-fly -->|
```

---

## 4. Cybersecurity & Cryptographic Architecture

### A. AES-256-GCM Envelope Encryption
- **Data Encryption Key (DEK)**: For every uploaded file, a unique 256-bit cryptographic key is generated using `crypto.randomBytes(32)`.
- **Initialization Vector (IV)**: A fresh 12-byte (96-bit) IV is generated for each file.
- **Authentication Tag**: GCM authenticated mode produces a 16-byte (128-bit) tag that guarantees file integrity and tamper-proofing.
- **Key Encryption Key (KEK / Master Key)**: The DEK is encrypted using a 256-bit Master Key managed independently in `storage/master.key` (or environment variable `MASTER_ENCRYPTION_KEY`). The plaintext DEK is immediately discarded from memory.
- **Encrypted Storage Key**: Saved as `kekIv:kekAuthTag:encryptedDek` in the database.

### B. Argon2id Password Hashing
- Recognized as the winner of the Password Hashing Competition (PHC).
- Configured with:
  - **Memory Cost**: 19,456 KiB (19 MiB)
  - **Time Cost (Iterations)**: 2
  - **Parallelism**: 1 thread
  - **Algorithm**: `argon2id` (hybrid of argon2i and argon2d resisting side-channel and GPU cracking attacks).

### C. Unpredictable QR Access Tokens
- 32-byte (256-bit) cryptographically secure random hex string.
- Raw tokens are **never stored in the database**. The database only contains `SHA-256(raw_qr_token)`. Even if the database is leaked, an attacker cannot construct the access URL.

---

## 5. The 4-Character Password Security Analysis

### Rationale
A 4-character password consists of:
- Uppercase letters (excluding ambiguous `O`, `I`): 24 characters
- Lowercase letters (excluding ambiguous `l`, `o`): 24 characters
- Numbers (excluding ambiguous `0`, `1`): 8 digits
- Safe symbols (`#`, `$`, `@`, `!`, `%`, `&`, `*`, `?`): 8 symbols
- Total keyspace: $(24 + 24 + 8 + 8)^4 = 64^4 = 16,777,216$ combinations.

### Why It Is Secure In SecureVault QR
1. **Unpredictable QR Token Gate**: An attacker cannot test passwords without first possessing the 256-bit random QR token.
2. **5-Attempt Lockout Defense**:
   - The backend tracks failed attempts per document access token.
   - If 5 incorrect attempts occur, access is frozen for **15 minutes**.
   - With at most 5 guesses per 15-minute window, the probability of guessing a 4-character password within 24 hours is:
     $$\frac{5 \times 96}{16,777,216} \approx 0.0028\%$$
3. **Argon2id Memory Hardness**: Prevents offline high-speed password brute force.
4. **Owner Revocation**: If suspicious activity is detected in the audit log, the owner can click **Regenerate QR** to instantly invalidate the token.

---

## 6. Database Schema & PostgreSQL Integration

The application contains complete DDL scripts in `backend/src/db/schema.sql`:

1. **`users`**: `id`, `full_name`, `email`, `password_hash`, `reset_token_hash`, `created_at`.
2. **`documents`**: `id`, `user_id`, `document_name`, `original_name`, `file_type`, `mime_type`, `file_size`, `encrypted_file_path`, `encrypted_storage_key`, `iv`, `auth_tag`, `expiry_date`, `access_status`.
3. **`document_access`**: `id`, `document_id`, `password_hash`, `qr_token_hash`, `failed_attempts`, `lockout_until`.
4. **`access_logs`**: `id`, `document_id`, `access_time`, `access_status`, `ip_address` (anonymized), `user_agent`, `access_method`.
5. **`sessions`**: `id`, `user_id`, `session_token_hash`, `expires_at`.

### Dual-Mode Database Adapter
The application includes a **Universal Database Adapter** (`backend/src/db/index.js`):
- **When PostgreSQL is running**: It connects using connection pooling (`pg.Pool`) and executes standard SQL queries.
- **When PostgreSQL is not configured yet**: It gracefully runs on a local atomic disk-backed store (`backend/storage/database.json`) using standard SQL parameterization (`$1, $2`). This enables instant zero-friction local development without requiring local database service setup!

To connect your PostgreSQL database:
```env
# In backend/.env:
DATABASE_URL=postgresql://postgres:password@localhost:5432/securevault_qr
```
Then run migrations:
```bash
npm run migrate
```

---

## 7. Development Stages Explained

| Stage | What Was Built | Primary Files Created | Why It Was Built |
|---|---|---|---|
| **STAGE 1: Setup & UI** | Full React + TypeScript + Tailwind UI foundation | `frontend/src/*`, `tailwind.config.js` | Provides the responsive SaaS design system, components, and layout. |
| **STAGE 2: Authentication** | User Registration, Login, Logout, Password Reset | `backend/src/routes/auth.js`, `frontend/src/context/AuthContext.tsx` | Ensures private user isolation; users only manage their own documents. |
| **STAGE 3: Database** | PostgreSQL Schema & Migration runner | `backend/src/db/schema.sql`, `migrate.js`, `index.js` | Persistent relational storage with constraints and audit capabilities. |
| **STAGE 4: Document Upload** | Multer memory storage, file validation, magic bytes | `backend/src/utils/fileValidator.js`, `backend/src/services/storageService.js` | Blocks malicious scripts/executables; validates true MIME signatures. |
| **STAGE 5: Encryption** | AES-256-GCM Envelope Encryption & KEK management | `backend/src/services/cryptoService.js`, `backend/src/config/keys.js` | Protects documents at rest; guarantees tamper-proofing via Auth Tags. |
| **STAGE 6: QR Generation** | 32-byte crypto tokens & PNG generation | `backend/src/services/qrService.js`, `frontend/src/components/QRCodeModal.tsx` | Generates scannable, downloadable, and printable QR codes. |
| **STAGE 7: 4-Char PIN** | Secure random generator, Argon2id hashing | `backend/src/services/passwordService.js`, `frontend/src/components/PinInput.tsx` | Generates unambiguous 4-char PIN; never stores plain text in the database. |
| **STAGE 8: Scan & Auth** | Public scan route, lockout timer, rate limiting | `backend/src/routes/access.js`, `frontend/src/pages/AccessPage.tsx` | Mobile-first authentication screen with 5-attempt brute force defense. |
| **STAGE 9: Decryption View** | On-the-fly streaming & temporary sessions | `backend/src/routes/access.js`, `frontend/src/pages/DocumentPreviewPage.tsx` | Streams decrypted bytes in-memory for authorized 15-minute windows. |
| **STAGE 10: Access History** | Privacy-masked audit trails & QR revocation | `backend/src/services/auditService.js`, `frontend/src/pages/HistoryPage.tsx` | Logs every access attempt (success, wrong PIN, lockout) with masked IPs. |
| **STAGE 11: Security Tests** | 15-point automated integration test suite | `backend/test/test-all.js` | Proves cryptographic, authentication, and lockout correctness. |
| **STAGE 12: Deployment Prep** | Root scripts, runner, production build | `scripts/dev.js`, `package.json`, `README.md` | One-command start for both frontend and backend. |

---

## 8. Quick Start & How to Run

### Prerequisites
- Node.js LTS (v18, v20, or v22)
- npm

### 1. Run the Entire Full-Stack Application (One Command)
From the project root (`securevault-qr`):
```bash
npm run dev
```
This concurrently starts:
- **Backend API**: `http://localhost:5050`
- **Frontend App**: `http://localhost:5173`

### 2. Run Individually (Optional)
**Backend:**
```bash
cd backend
npm run dev
```

**Frontend:**
```bash
cd frontend
npm run dev
```

### 3. Open in Browser
Open [http://localhost:5173](http://localhost:5173) to create your account and start uploading documents.

---

## 9. Automated Test Suite & Verification

The project includes an end-to-end integration and security test suite testing 15 critical scenarios:
1. System Health Check
2. User Registration (Argon2id password hashing)
3. User Login & JWT Session issuance
4. Document Upload with AES-256-GCM Envelope Encryption
5. 4-Character Password Generation & Hashing
6. Public QR Code Info Endpoint (Safe metadata only)
7. 4-Character Password Verification (Incorrect attempt rejection)
8. 4-Character Password Verification (Correct password authorization)
9. Authorized Document Decryption & Byte-Level Integrity Check
10. Unauthorized Access Rejection (No token)
11. Brute Force Protection (5 Failed Attempts Lockout - HTTP 429)
12. QR Code Regeneration (Old token revoked, lockout reset)
13. Old QR Token Verification (Returns 404)
14. Access History & Privacy Audit Logging
15. Permanent Document Deletion & Storage Purge

To run the test suite:
```bash
npm test
```
**Result**: `ALL 15 INTEGRATION & SECURITY TESTS PASSED (100%)`.

---

## 10. REST API Documentation

### Authentication (`/api/auth`)
- `POST /api/auth/register`: `{ full_name, email, password, confirm_password }`
- `POST /api/auth/login`: `{ email, password }`
- `POST /api/auth/logout`: Clears session cookie
- `GET /api/auth/me`: Returns logged-in user profile
- `POST /api/auth/forgot-password`: Generates reset token
- `POST /api/auth/reset-password`: `{ token, new_password, confirm_password }`
- `PUT /api/auth/profile`: `{ full_name }`
- `PUT /api/auth/change-password`: `{ current_password, new_password, confirm_password }`

### Documents (`/api/documents`)
- `POST /api/documents/upload`: `multipart/form-data` with `files`, optional `custom_password`, `expiry_date`
- `GET /api/documents`: List owner documents with `search`, `file_type`, `status`, `page`, `limit`
- `GET /api/documents/stats`: Returns dashboard metrics
- `GET /api/documents/:id`: Document details
- `GET /api/documents/:id/download`: Decrypts and downloads file
- `GET /api/documents/:id/preview`: Streams decrypted file for in-browser preview
- `GET /api/documents/:id/qr-download`: Downloads QR code as PNG image
- `PUT /api/documents/:id/password`: `{ new_password }` or `{ auto_generate: true }`
- `POST /api/documents/:id/regenerate-qr`: Revokes old QR and generates fresh token
- `PUT /api/documents/:id/status`: `{ access_status: 'active' | 'revoked', expiry_date }`
- `DELETE /api/documents/:id`: Permanently deletes document and encrypted storage

### Public Access Flow (`/api/access`)
- `GET /api/access/:qrToken/info`: Public safe metadata (name, format, size, lockout status)
- `POST /api/access/:qrToken/verify`: `{ password }` -> Returns `accessSessionToken`
- `GET /api/access/:qrToken/preview`: Streams decrypted document with authorized session
- `GET /api/access/:qrToken/download`: Downloads decrypted document with authorized session

### Access History (`/api/history`)
- `GET /api/history`: Returns audit trail logs with anonymized IPs and timestamps

---

## License
MIT License. Built for secure document distribution.
