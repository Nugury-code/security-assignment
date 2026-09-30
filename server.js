// 과제 8 — 카드 1: 무엇을 잠글지 먼저 가른다
//
// 이 서버가 하는 일은 지금 딱 두 가지뿐입니다.
//  1) index.html 등 공개 파일을 그대로 서빙한다.
//  2) "비공개 자료" 엔드포인트(/api/private)는 아직 아무도 로그인할 방법이 없으므로
//     언제나 401(Unauthorized)로 거절한다.
//
// 외부 패키지 없이 Node.js 기본 http/fs 모듈만 쓴다 — 별도 설치(npm install) 없이
// `node server.js`만으로 바로 실행된다.
//
// 패스키 등록/로그인(카드 2~3)이 생기면, 그때 가서 "유효한 로그인 세션이 있으면 통과"하는
// 조건을 이 자리에 추가할 예정입니다. 지금은 그 로직을 미리 끼워 넣지 않습니다.

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;

// 비공개 영역에 들어갈 실제 내용물. index.html에는 절대 심지 않고 서버 메모리에만 둔다.
// (지금은 예시로 채워 둔 자리표시자 — 나중에 실제 내용으로 바꾸면 됨)
const PRIVATE_ITEMS = [
  '진행 중인 프로젝트 메모: (예시) 공모전용 프로토타입 기획 초안 정리 중',
  '지원 예정 회사·직무 목록: (예시) 관심 기업 리스트와 마감일 정리',
  '최근 회고 노트: (예시) 이번 주 배운 점과 다음 주 목표'
];

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

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

const server = http.createServer((req, res) => {
  if (req.url.startsWith('/api/private')) {
    // TODO(카드 2~3): 여기서 패스키 로그인 세션을 확인해서, 유효하면 아래 401 대신
    // sendJson(res, 200, { items: PRIVATE_ITEMS })를 돌려주도록 바꾼다. 지금은 그 세션 자체가
    // 존재하지 않으므로 무조건 거절하는 것이 정확한 동작이다.
    return sendJson(res, 401, { error: 'unauthorized', message: '패스키 로그인이 필요합니다.' });
  }
  serveStatic(req, res);
});

server.listen(PORT, () => {
  console.log(`서버 실행 중: http://localhost:${PORT}`);
});
