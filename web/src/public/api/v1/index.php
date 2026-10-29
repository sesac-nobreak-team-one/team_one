<?php
declare(strict_types=1);

// [레거시 v1] 전용 프런트 컨트롤러. v2(public/api/index.php)와 완전히 분리되어 있다.
// 공식 API 문서(openapi.yaml)에는 포함하지 않는다.
// 반드시 격리 환경에서만 켜둔다 — 인터넷 비노출, 팀 IP만 접근 허용.

require __DIR__ . '/../../../vendor/autoload.php';

use App\Api\V1\DiagnosticsController;
use App\Api\V1\LegacyUserController;
use App\Core\Database;
use App\Core\HttpException;
use App\Core\Logger;
use App\Core\Request;
use App\Core\Response;
use App\Core\Security;
use App\Core\TokenError;
use App\Repositories\UserRepository;

ini_set('display_errors', '0');
date_default_timezone_set('Asia/Seoul');

$startedAt = microtime(true);
$requestId = $_SERVER['UNIQUE_ID'] ?? bin2hex(random_bytes(8));
header('X-Request-Id: ' . $requestId);

$config = require __DIR__ . '/../../../config/config.php';
$logger = new Logger(__DIR__ . '/../../../logs/app.log');
$callerId = null;   // JWT에서 뽑은 호출자 id. 인증 통과 시 로그에 남긴다(= 공격 귀속 가능).

// v2와 같은 모양으로 로그를 남긴다. path 에 공격 문자열이 그대로 찍혀서 탐지에 쓸 수 있다.
register_shutdown_function(function () use ($logger, &$callerId, $requestId, $startedAt) {
    $logger->write([
        'timestamp'      => date('c', (int) $startedAt),
        'request_id'     => $requestId,
        // mod_remoteip가 WAF/프록시 뒤의 실제 클라이언트 IP로 바꿔 둔 값이다 (X-Forwarded-For를 직접 읽지 않는다: 위조 가능)
        'client_ip'      => $_SERVER['REMOTE_ADDR'] ?? '',
        'method'         => $_SERVER['REQUEST_METHOD'] ?? '',
        'path'           => Logger::cut($_SERVER['REQUEST_URI'] ?? '', 2000),
        'status'         => http_response_code() ?: 200,
        'response_bytes' => Response::bytes(),
        'user_id'        => $callerId,   // 인증(JWT)만 통과하면 누구의 요청인지 기록된다
        'duration_ms'    => round((microtime(true) - $startedAt) * 1000, 1),
        'user_agent'     => Logger::cut($_SERVER['HTTP_USER_AGENT'] ?? '', 300),
    ]);
});

try {
    $path   = rtrim((string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH), '/');
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

    $db = Database::connect($config['db']);

    // ─────────────────────────────────────────────────────────────────────────
    // [레거시 v1 — 의도된 설계] "토큰만 있으면 신뢰한다"
    //
    // 인증(JWT 서명·만료)만 확인하고, 그 이후의 인가(소유권·권한) 검사는 전혀 하지 않는다.
    //   → 아무 계정이나 로그인해 받은 유효한 토큰 하나면,
    //     - /users/{id}      : 내 id가 아니어도 남의 개인정보를 조회 (BOLA / OWASP API #1)
    //     - /diagnostics/ping: 명령어 주입(RCE) 그대로 노출
    // 실제 2022년식 침해의 전형: 인증은 됐으나 "객체 수준 인가"가 비어 있던 형태.
    // (v2는 AuthMiddleware가 토큰 검증 + 사용자 조회까지 하고, 각 컨트롤러가 소유권을 확인한다.)
    // ─────────────────────────────────────────────────────────────────────────
    $security = new Security($config['jwt']);
    $token    = Request::capture()->bearerToken();
    if ($token === null) {
        throw new HttpException(401, '인증이 필요합니다');
    }
    try {
        // 서명과 만료(exp)만 본다. 이 토큰이 "요청한 그 리소스의 주인"인지는 비교하지 않는다.
        $callerId = $security->decodeToken($token);
    } catch (TokenError $e) {
        throw new HttpException(401, '유효하지 않은 토큰입니다');
    }

    if ($method === 'GET' && preg_match('#^/api/v1/users/([^/]+)$#', $path, $m)) {
        (new LegacyUserController(new UserRepository($db)))->show($m[1]);
    } elseif ($method === 'GET' && $path === '/api/v1/diagnostics/ping') {
        $host = $_GET['host'] ?? '';
        (new DiagnosticsController())->ping((string) $host);
    } else {
        Response::json(['detail' => '존재하지 않는 경로입니다'], 404);
    }
} catch (HttpException $e) {
    Response::json(['detail' => $e->getMessage()], $e->getStatus());
} catch (\Throwable $e) {
    error_log('[shop-api-v1] ' . get_class($e) . ': ' . $e->getMessage());
    Response::json(['detail' => '서버 내부 오류'], 500);
}