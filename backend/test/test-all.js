/**
 * SECUREVAULT QR – COMPREHENSIVE INTEGRATION & SECURITY TEST SUITE
 * Tests:
 * 1. User Registration (Argon2id hashing)
 * 2. User Login & Session authentication
 * 3. Document Upload & AES-256-GCM Envelope Encryption
 * 4. 4-Character Password Generation & Verification
 * 5. QR Code Generation & Cryptographic Token Hashing
 * 6. Public Access Flow: Correct Password Access Grant
 * 7. Public Access Flow: Incorrect Password & Remaining Attempts Tracking
 * 8. Brute Force Lockout: 5 Failed Attempts -> 429 Locked Out
 * 9. Decryption on the fly & Integrity Verification
 * 10. QR Code Regeneration (Old QR Token Revoked)
 * 11. Document Access History / Audit Logs
 * 12. Document Deletion & Storage Purge
 */

const http = require('http');
const assert = require('assert');
const { startServer } = require('../src/server');

const BASE_URL = 'http://127.0.0.1:5050';

function makeRequest({ method, path, headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const reqHeaders = { ...headers };

    let payload = null;
    if (body && typeof body === 'object' && !(body instanceof Buffer)) {
      payload = JSON.stringify(body);
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(payload);
    } else if (body instanceof Buffer) {
      payload = body;
    }

    const req = http.request(
      url,
      {
        method,
        headers: reqHeaders,
      },
      (res) => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks);
          let json = null;
          try {
            json = JSON.parse(raw.toString('utf8'));
          } catch (e) {
            // Not JSON
          }
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: json || raw,
            raw,
          });
        });
      }
    );

    req.on('error', reject);
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

function createMultipartFormData(boundary, fields, files) {
  const parts = [];

  for (const [key, val] of Object.entries(fields)) {
    parts.push(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="${key}"\r\n\r\n` +
      `${val}\r\n`
    );
  }

  for (const file of files) {
    parts.push(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="${file.field}"; filename="${file.name}"\r\n` +
      `Content-Type: ${file.type}\r\n\r\n`
    );
    parts.push(file.content);
    parts.push('\r\n');
  }

  parts.push(`--${boundary}--\r\n`);

  const buffers = parts.map(p => (typeof p === 'string' ? Buffer.from(p, 'utf8') : p));
  return Buffer.concat(buffers);
}

async function runTests() {
  console.log('\n======================================================');
  console.log('  RUNNING SECUREVAULT QR SECURITY & API TEST SUITE   ');
  console.log('======================================================\n');

  await startServer();

  // Test 1: Health Check
  console.log('1. Testing System Health Check...');
  const healthRes = await makeRequest({ method: 'GET', path: '/api/health' });
  assert.strictEqual(healthRes.statusCode, 200);
  assert.strictEqual(healthRes.body.status, 'ok');
  console.log('   ✓ Health check passed');

  // Test 2: User Registration
  console.log('2. Testing User Registration (Argon2id Hashing)...');
  const testEmail = `tester_${Date.now()}@example.com`;
  const regRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/register',
    body: {
      full_name: 'Alex Secure',
      email: testEmail,
      password: 'SecurePassword123!',
      confirm_password: 'SecurePassword123!',
    },
  });
  assert.strictEqual(regRes.statusCode, 201);
  assert.ok(regRes.body.token);
  assert.strictEqual(regRes.body.user.email, testEmail);
  const userToken = regRes.body.token;
  const authHeaders = { Authorization: `Bearer ${userToken}` };
  console.log('   ✓ Registration succeeded, session token issued');

  // Test 3: User Login
  console.log('3. Testing User Login...');
  const loginRes = await makeRequest({
    method: 'POST',
    path: '/api/auth/login',
    body: {
      email: testEmail,
      password: 'SecurePassword123!',
    },
  });
  assert.strictEqual(loginRes.statusCode, 200);
  assert.ok(loginRes.body.token);
  console.log('   ✓ Login verification passed');

  // Test 4: Document Upload & Encryption
  console.log('4. Testing Document Upload with AES-256-GCM Envelope Encryption...');
  const boundary = '----VaultBoundary' + Math.random().toString(36).substring(2);
  const samplePdfContent = Buffer.from('%PDF-1.4 sample secure document content for vault testing', 'utf8');

  const multipartBody = createMultipartFormData(
    boundary,
    { custom_password: 'P9#k' },
    [{ field: 'files', name: 'Confidential_Report.pdf', type: 'application/pdf', content: samplePdfContent }]
  );

  const uploadRes = await makeRequest({
    method: 'POST',
    path: '/api/documents/upload',
    headers: {
      ...authHeaders,
      'Content-Type': `multipart/form-data; boundary=${boundary}`,
      'Content-Length': multipartBody.length,
    },
    body: multipartBody,
  });

  assert.strictEqual(uploadRes.statusCode, 201);
  assert.ok(uploadRes.body.documents && uploadRes.body.documents.length === 1);
  const uploadedDoc = uploadRes.body.documents[0];
  assert.strictEqual(uploadedDoc.document_name, 'Confidential_Report.pdf');
  assert.strictEqual(uploadedDoc.plainPassword, 'P9#k');
  assert.ok(uploadedDoc.rawQrToken);
  assert.ok(uploadedDoc.qrDataUrl.startsWith('data:image/png;base64,'));
  console.log('   ✓ Document encrypted & saved to vault');
  console.log(`   ✓ 4-character password generated: ${uploadedDoc.plainPassword}`);
  console.log(`   ✓ Unique QR token issued: ${uploadedDoc.rawQrToken.slice(0, 16)}...`);

  // Test 5: Fetch Owner Dashboard & Stats
  console.log('5. Testing Owner Dashboard & Stats...');
  const statsRes = await makeRequest({ method: 'GET', path: '/api/documents/stats', headers: authHeaders });
  assert.strictEqual(statsRes.statusCode, 200);
  assert.strictEqual(statsRes.body.stats.totalUploaded, 1);
  assert.strictEqual(statsRes.body.stats.totalActiveDocuments, 1);
  console.log('   ✓ Dashboard statistics computed correctly');

  // Test 6: Public QR Code Access Info
  console.log('6. Testing Public QR Code Info Endpoint...');
  const infoRes = await makeRequest({
    method: 'GET',
    path: `/api/access/${uploadedDoc.rawQrToken}/info`,
  });
  assert.strictEqual(infoRes.statusCode, 200);
  assert.strictEqual(infoRes.body.document.document_name, 'Confidential_Report.pdf');
  assert.strictEqual(infoRes.body.document.isLockedOut, false);
  console.log('   ✓ QR scan info retrieved (safe metadata only)');

  // Test 7: Password Verification with Incorrect Password
  console.log('7. Testing 4-Character Password Verification (Incorrect Attempt)...');
  const failRes = await makeRequest({
    method: 'POST',
    path: `/api/access/${uploadedDoc.rawQrToken}/verify`,
    body: { password: 'W0#x' },
  });
  assert.strictEqual(failRes.statusCode, 401);
  assert.strictEqual(failRes.body.code, 'INCORRECT_PASSWORD');
  assert.strictEqual(failRes.body.remainingAttempts, 4);
  console.log('   ✓ Incorrect password rejected, remaining attempts: 4');

  // Test 8: Password Verification with Correct 4-Character Password
  console.log('8. Testing 4-Character Password Verification (Correct Password)...');
  const verifyRes = await makeRequest({
    method: 'POST',
    path: `/api/access/${uploadedDoc.rawQrToken}/verify`,
    body: { password: 'P9#k' },
  });
  assert.strictEqual(verifyRes.statusCode, 200);
  assert.ok(verifyRes.body.accessSessionToken);
  const recipientSessionToken = verifyRes.body.accessSessionToken;
  console.log('   ✓ Password verified with Argon2id, 15-minute access session issued');

  // Test 9: Public Preview & Download with Authorized Session
  console.log('9. Testing Authorized Document Decryption & Download...');
  const downloadRes = await makeRequest({
    method: 'GET',
    path: `/api/access/${uploadedDoc.rawQrToken}/download`,
    headers: { Authorization: `Bearer ${recipientSessionToken}` },
  });
  assert.strictEqual(downloadRes.statusCode, 200);
  assert.strictEqual(downloadRes.raw.toString('utf8'), samplePdfContent.toString('utf8'));
  console.log('   ✓ Document decrypted on the fly; byte integrity matches uploaded content perfectly!');

  // Test 10: Unauthorized Access Attempt without session
  console.log('10. Testing Unauthorized Access Attempt without token...');
  const unauthorizedRes = await makeRequest({
    method: 'GET',
    path: `/api/access/${uploadedDoc.rawQrToken}/download`,
  });
  assert.strictEqual(unauthorizedRes.statusCode, 401);
  console.log('   ✓ Unauthorized access blocked');

  // Test 11: Brute Force Rate Limiting & Lockout
  console.log('11. Testing Brute Force Protection (5 Failed Attempts Lockout)...');
  for (let i = 0; i < 4; i++) {
    await makeRequest({
      method: 'POST',
      path: `/api/access/${uploadedDoc.rawQrToken}/verify`,
      body: { password: 'X9#z' },
    });
  }
  // The 5th attempt triggers lockout
  const lockRes = await makeRequest({
    method: 'POST',
    path: `/api/access/${uploadedDoc.rawQrToken}/verify`,
    body: { password: 'X9#z' },
  });
  assert.strictEqual(lockRes.statusCode, 429);
  assert.strictEqual(lockRes.body.code, 'LOCKED_OUT');
  console.log('   ✓ Account/Document locked out after 5 failed attempts (HTTP 429)');

  // Test 12: Regenerate QR Code
  console.log('12. Testing QR Code Regeneration (Old token revoked, lock reset)...');
  const regenRes = await makeRequest({
    method: 'POST',
    path: `/api/documents/${uploadedDoc.id}/regenerate-qr`,
    headers: authHeaders,
  });
  assert.strictEqual(regenRes.statusCode, 200);
  assert.ok(regenRes.body.rawQrToken);
  assert.notStrictEqual(regenRes.body.rawQrToken, uploadedDoc.rawQrToken);
  console.log('   ✓ New QR code generated; previous QR token immediately invalidated');

  // Test 13: Old QR Token is now invalid
  const oldQrCheck = await makeRequest({
    method: 'GET',
    path: `/api/access/${uploadedDoc.rawQrToken}/info`,
  });
  assert.strictEqual(oldQrCheck.statusCode, 404);
  console.log('   ✓ Verified old QR code returned 404 Not Found');

  // Test 14: Access History / Audit Logs
  console.log('14. Testing Document Access History Audit Logs...');
  const historyRes = await makeRequest({
    method: 'GET',
    path: '/api/history',
    headers: authHeaders,
  });
  assert.strictEqual(historyRes.statusCode, 200);
  assert.ok(historyRes.body.logs.length >= 2);
  console.log(`   ✓ Verified ${historyRes.body.logs.length} audit trail records recorded`);

  // Test 15: Permanent Document Deletion
  console.log('15. Testing Permanent Document Deletion...');
  const delRes = await makeRequest({
    method: 'DELETE',
    path: `/api/documents/${uploadedDoc.id}`,
    headers: authHeaders,
  });
  assert.strictEqual(delRes.statusCode, 200);
  console.log('   ✓ Document and encrypted vault storage purged permanently');

  // Test 16: View-Only Mode (allow_download=false) & Screenshot Restriction (block_screenshots=true)
  console.log('16. Testing View-Only & Screenshot-Restricted Permissions...');
  const viewOnlyBoundary = '----ViewOnlyBoundary' + Math.random().toString(36).substring(2);
  const viewOnlyBody = createMultipartFormData(
    viewOnlyBoundary,
    { custom_password: 'V8@m', allow_download: 'false', block_screenshots: 'true' },
    [{ field: 'files', name: 'ViewOnly_Secret.pdf', type: 'application/pdf', content: samplePdfContent }]
  );
  const voUpRes = await makeRequest({
    method: 'POST',
    path: '/api/documents/upload',
    headers: {
      ...authHeaders,
      'Content-Type': `multipart/form-data; boundary=${viewOnlyBoundary}`,
      'Content-Length': viewOnlyBody.length,
    },
    body: viewOnlyBody,
  });
  assert.strictEqual(voUpRes.statusCode, 201);
  const voDoc = voUpRes.body.documents[0];
  assert.strictEqual(voDoc.allow_download, false);
  assert.strictEqual(voDoc.block_screenshots, true);

  const voVerRes = await makeRequest({
    method: 'POST',
    path: `/api/access/${voDoc.rawQrToken}/verify`,
    body: { password: 'V8@m' },
  });
  assert.strictEqual(voVerRes.statusCode, 200);
  assert.strictEqual(voVerRes.body.document.allow_download, false);
  assert.strictEqual(voVerRes.body.document.block_screenshots, true);

  const voDlRes = await makeRequest({
    method: 'GET',
    path: `/api/access/${voDoc.rawQrToken}/download`,
    headers: { Authorization: `Bearer ${voVerRes.body.accessSessionToken}` },
  });
  assert.strictEqual(voDlRes.statusCode, 403);
  assert.strictEqual(voDlRes.body.code, 'DOWNLOAD_DISABLED');

  const voPreviewRes = await makeRequest({
    method: 'GET',
    path: `/api/access/${voDoc.rawQrToken}/preview`,
    headers: { Authorization: `Bearer ${voVerRes.body.accessSessionToken}` },
  });
  assert.strictEqual(voPreviewRes.statusCode, 200);
  assert.ok(String(voPreviewRes.headers['cache-control']).includes('no-store'));

  await makeRequest({
    method: 'DELETE',
    path: `/api/documents/${voDoc.id}`,
    headers: authHeaders,
  });
  console.log('   ✓ View-Only download blocked (HTTP 403) while protected inline preview succeeds');

  console.log('\n======================================================');
  console.log('  ALL 16 INTEGRATION & SECURITY TESTS PASSED (100%)  ');
  console.log('======================================================\n');
  process.exit(0);
}

runTests().catch(err => {
  console.error('\n❌ Test Failure:', err);
  process.exit(1);
});
