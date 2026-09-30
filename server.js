// 과제 8
//
// 카드 1: 공개 페이지는 그대로 서빙하고, 비공개 자료(/api/private)는 로그인 수단이
//         생기기 전까지 무조건 401로 거절한다.
// 카드 2: 패스키 "등록" 절차를 구현한다.
//         - 서버가 매번 새 일회용 질문(challenge)을 만들어 세션에 잠깐 보관한다.
//         - 브라우저가 돌려준 응답을 그 질문 값과 맞춰보고(verifyRegistrationResponse),
//           맞으면 "공개키"만 data/credentials.json에 저장한다. 개인키는 처음부터
//           서버로 전송되지 않는다 — WebAuthn 표준 자체가 개인키를 기기 밖으로
//           내보내지 않는 방식으로 설계되어 있다.
//
// 카드 3: 패스키 "로그인" 절차를 구현한다.
//         - 로그인 시도마다 서버가 새 질문을 만들어 보내고, 딱 한 번만 쓸 수 있다
//           (검증 성공/실패 상관없이 바로 폐기 — 재사용·재생 공격 방지).
//         - 브라우저가 개인키로 서명한 응답을, 저장해 둔 공개키로 확인한다
//           (verifyAuthenticationResponse). 통과해야만 sid 쿠키를 "로그인됨"으로
//           표시하고, 그때부터 /api/private이 401 대신 진짜 내용을 돌려준다.
//         - "로그인됨" 표시는 서버 메모리의 세션(authenticatedSids)으로 하며,
//           비밀번호·패스키 원문이 아니라 무작위로 생성된 sid 쿠키 값 하나로만
//           사람을 알아본다. 로그아웃하면 그 표시를 지운다.
//
// ⚠️ 알아두어야 할 점: 지금 /register.html과 /api/register/* 는 누구나 접근할 수 있다.
// 즉 이 사이트를 실제로 배포한 뒤에는, 아무나 이 페이지에 들어와서 "자기" 패스키를
// 등록해 비공개 영역에 들어올 수 있다는 뜻이다. 카드 3까지 끝나고 나서(또는 배포 전에)
// 반드시 이 등록 절차 자체를 나만 쓸 수 있게 막아야 한다 — 아직 안 막은 상태이고,
// 이건 카드 5의 "아직 못 맞은 것"에 정직하게 적어야 할 부분이다.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const CREDENTIALS_FILE = path.join(DATA_DIR, 'credentials.json');

// 비공개 영역에 들어갈 실제 내용물. index.html에는 절대 심지 않고 서버 메모리에만 둔다.
// (지금은 예시로 채워 둔 자리표시자 — 나중에 실제 내용으로 바꾸면 됨)
const PRIVATE_ITEMS = [
  '진행 중인 프로젝트 메모: (예시) 공모전용 프로토타입 기획 초안 정리 중',
  '지원 예정 회사·직무 목록: (예시) 관심 기업 리스트와 마감일 정리',
  '최근 회고 노트: (예시) 이번 주 배운 점과 다음 주 목표'
];

// 등록 중간에만 잠깐 살아있는 challenge 저장소. sid(세션 쿠키) 하나당 하나씩,
// 검증에 성공하거나 5분이 지나면 사라진다. 서버가 재시작되면 당연히 다 날아간다 —
// "등록 도중"의 임시 상태일 뿐이라 파일로 저장할 필요가 없다.
const pendingChallenges = new Map();
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

// 로그인 중간에만 잠깐 살아있는 challenge 저장소(등록용과 별개). sid당 하나,
// 검증 뒤(성공이든 실패든) 바로 지워서 같은 질문을 두 번 못 쓰게 한다.
const pendingLoginChallenges = new Map();

// "로그인됨" 표시. sid -> 만료 시각(ms). 비밀번호도, 패스키 원문도 아니고
// 그냥 무작위 문자열(sid)과 시각 하나로만 사람을 구분한다 — 이게 우리 세션이다.
const authenticatedSids = new Map();
const SESSION_TTL_MS = 30 * 60 * 1000; // 30분 뒤 자동 로그아웃

// ---------- 저장된 패스키(공개키) 읽기/쓰기 ----------

function loadCredentials() {
  try {
    const raw = fs.readFileSync(CREDENTIALS_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    return [];
  }
}

function saveCredentials(list) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(CREDENTIALS_FILE, JSON.stringify(list, null, 2));
}

// ---------- 아주 작은 세션(sid 쿠키) ----------

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx > -1) {
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      if (k) out[k] = decodeURIComponent(v);
    }
  });
  return out;
}

function getProto(req) {
  return req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
}

function ensureSid(req, res) {
  const cookies = parseCookies(req);
  if (cookies.sid) return cookies.sid;
  const sid = crypto.randomBytes(18).toString('base64url');
  const secure = getProto(req) === 'https' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; Path=/; SameSite=Lax${secure}`);
  return sid;
}

// WebAuthn의 rpID(신뢰 당사자 ID)는 이 사이트가 실제로 서빙되는 도메인과 정확히
// 일치해야 한다. 로컬에서는 "localhost", 나중에 배포하면 그 도메인으로 자동으로
// 바뀌도록 요청 헤더에서 읽어온다(하드코딩하지 않음).
function getRpID(req) {
  return (req.headers.host || 'localhost').split(':')[0];
}

function getOrigin(req) {
  return `${getProto(req)}://${req.headers.host}`;
}

// ---------- 공통 유틸 ----------

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1e6) reject(new Error('payload too large'));
    });
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

function serveStatic(req, res) {
  let reqPath = decodeURIComponent(req.url.split('?')[0]);
  if (reqPath === '/') reqPath = '/index.html';

  // 상위 폴더로 빠져나가는 경로(../)를 막는다.
  const filePath = path.normalize(path.join(ROOT, reqPath));
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Not Found');
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------- 라우팅 ----------

const server = http.createServer(async (req, res) => {
  const urlPath = req.url.split('?')[0];

  try {
    // 카드 1 → 카드 3: 비공개 자료 — 로그인 세션이 유효할 때만 내용을 돌려준다.
    if (urlPath === '/api/private') {
      const cookies = parseCookies(req);
      const sid = cookies.sid;
      const expiresAt = sid && authenticatedSids.get(sid);
      if (expiresAt && expiresAt > Date.now()) {
        return sendJson(res, 200, { items: PRIVATE_ITEMS });
      }
      if (expiresAt) authenticatedSids.delete(sid); // 만료된 세션 정리
      return sendJson(res, 401, { error: 'unauthorized', message: '패스키 로그인이 필요합니다.' });
    }

    // 카드 2: 패스키 등록 — 1) 서버가 질문(challenge)을 만들어 보낸다.
    if (urlPath === '/api/register/options' && req.method === 'GET') {
      const sid = ensureSid(req, res);
      const existing = loadCredentials();

      const options = await generateRegistrationOptions({
        rpName: '원석연의 소개 페이지',
        rpID: getRpID(req),
        userName: 'owner',
        userDisplayName: '원석연',
        attestationType: 'none',
        excludeCredentials: existing.map((c) => ({ id: c.id })),
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred'
        }
      });

      pendingChallenges.set(sid, { challenge: options.challenge, createdAt: Date.now() });
      return sendJson(res, 200, options);
    }

    // 카드 2: 패스키 등록 — 2) 브라우저가 돌려준 응답을 검증하고, 맞으면 공개키만 저장한다.
    if (urlPath === '/api/register/verify' && req.method === 'POST') {
      const cookies = parseCookies(req);
      const sid = cookies.sid;
      const pending = sid && pendingChallenges.get(sid);

      if (!pending) {
        return sendJson(res, 400, { error: 'no_pending_challenge', message: '등록을 다시 시작해 주세요.' });
      }
      if (Date.now() - pending.createdAt > CHALLENGE_TTL_MS) {
        pendingChallenges.delete(sid);
        return sendJson(res, 400, { error: 'challenge_expired', message: '시간이 너무 지났습니다. 다시 시도해 주세요.' });
      }

      const body = await readJsonBody(req);
      const name = (body.name || '').trim();
      if (!name) {
        return sendJson(res, 400, { error: 'name_required', message: '패스키 이름을 입력해 주세요.' });
      }
      if (!body.credential) {
        return sendJson(res, 400, { error: 'credential_required' });
      }

      let verification;
      try {
        verification = await verifyRegistrationResponse({
          response: body.credential,
          expectedChallenge: pending.challenge,
          expectedOrigin: getOrigin(req),
          expectedRPID: getRpID(req),
          // 등록 시 userVerification을 'preferred'(있으면 쓰고 없어도 통과)로 요청했으므로,
          // 검증 단계에서도 이를 무조건 강제(true)하지 않도록 맞춘다.
          requireUserVerification: false
        });
      } catch (err) {
        return sendJson(res, 400, { error: 'verification_error', message: String(err.message || err) });
      }

      pendingChallenges.delete(sid); // 한 번 쓴 challenge는 맞든 틀리든 바로 폐기(재사용 불가)

      if (!verification.verified || !verification.registrationInfo) {
        return sendJson(res, 400, { error: 'not_verified', message: '등록을 확인하지 못했습니다.' });
      }

      const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
      const stored = loadCredentials();
      stored.push({
        id: credential.id, // 공개 식별자(Base64URL) — 비밀번호 아님
        publicKey: Buffer.from(credential.publicKey).toString('base64'), // 공개키 — 비밀번호 아님, 유출돼도 로그인에 못 씀
        counter: credential.counter,
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        name,
        createdAt: new Date().toISOString()
      });
      saveCredentials(stored);

      return sendJson(res, 200, { success: true });
    }

    // 등록된 패스키 목록(이름 + 등록일만 — 공개키 원문은 data/credentials.json 파일에서 직접 확인)
    if (urlPath === '/api/passkeys' && req.method === 'GET') {
      const stored = loadCredentials();
      return sendJson(res, 200, {
        items: stored.map((c) => ({ name: c.name, createdAt: c.createdAt }))
      });
    }

    // 카드 3: 패스키 로그인 — 1) 서버가 로그인용 질문(challenge)을 만들어 보낸다.
    if (urlPath === '/api/login/options' && req.method === 'GET') {
      const sid = ensureSid(req, res);
      const existing = loadCredentials();

      if (existing.length === 0) {
        return sendJson(res, 400, { error: 'no_credentials', message: '등록된 패스키가 없습니다. 먼저 등록해 주세요.' });
      }

      const options = await generateAuthenticationOptions({
        rpID: getRpID(req),
        allowCredentials: existing.map((c) => ({ id: c.id })),
        userVerification: 'preferred'
      });

      pendingLoginChallenges.set(sid, { challenge: options.challenge, createdAt: Date.now() });
      return sendJson(res, 200, options);
    }

    // 카드 3: 패스키 로그인 — 2) 서명을 저장된 공개키로 확인하고, 맞으면 세션을 로그인 상태로 표시한다.
    if (urlPath === '/api/login/verify' && req.method === 'POST') {
      const cookies = parseCookies(req);
      const sid = cookies.sid;
      const pending = sid && pendingLoginChallenges.get(sid);

      if (!pending) {
        return sendJson(res, 400, { error: 'no_pending_challenge', message: '로그인을 다시 시작해 주세요.' });
      }
      // 성공하든 실패하든 이 질문은 바로 폐기한다 — 같은 질문으로 두 번 로그인 시도를 못 하게 막는 지점.
      pendingLoginChallenges.delete(sid);

      if (Date.now() - pending.createdAt > CHALLENGE_TTL_MS) {
        return sendJson(res, 400, { error: 'challenge_expired', message: '시간이 너무 지났습니다. 다시 시도해 주세요.' });
      }

      const body = await readJsonBody(req);
      if (!body.credential || !body.credential.id) {
        return sendJson(res, 400, { error: 'credential_required' });
      }

      const stored = loadCredentials();
      const match = stored.find((c) => c.id === body.credential.id);
      if (!match) {
        return sendJson(res, 400, { error: 'unknown_credential', message: '등록되지 않은 패스키입니다.' });
      }

      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response: body.credential,
          expectedChallenge: pending.challenge,
          expectedOrigin: getOrigin(req),
          expectedRPID: getRpID(req),
          credential: {
            id: match.id,
            publicKey: Buffer.from(match.publicKey, 'base64'),
            counter: match.counter
          },
          requireUserVerification: false
        });
      } catch (err) {
        return sendJson(res, 400, { error: 'verification_error', message: String(err.message || err) });
      }

      if (!verification.verified) {
        return sendJson(res, 400, { error: 'not_verified', message: '서명 확인에 실패했습니다.' });
      }

      // 재생 공격 방지용 카운터 갱신(다중 기기 동기화 패스키는 보통 0으로 고정되어 있을 수 있음).
      match.counter = verification.authenticationInfo.newCounter;
      saveCredentials(stored);

      authenticatedSids.set(sid, Date.now() + SESSION_TTL_MS);
      return sendJson(res, 200, { success: true });
    }

    // 로그아웃 — 이 sid의 "로그인됨" 표시만 지운다. 쿠키 자체도 만료시켜 정리한다.
    if (urlPath === '/api/logout' && req.method === 'POST') {
      const cookies = parseCookies(req);
      if (cookies.sid) authenticatedSids.delete(cookies.sid);
      res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
      return sendJson(res, 200, { success: true });
    }

    serveStatic(req, res);
  } catch (err) {
    sendJson(res, 500, { error: 'server_error', message: String(err.message || err) });
  }
});

server.listen(PORT, () => {
  console.log(`서버 실행 중: http://localhost:${PORT}`);
});
