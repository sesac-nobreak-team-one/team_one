<?php
declare(strict_types=1);

namespace App\Api\V1;

use App\Core\Response;

/**
 * [레거시 v1 — 의도된 취약점] 입력검증 누락으로 인한 원격 명령 실행
 *
 * "서버 네트워크 상태를 확인하는 진단용 기능"이라는 명목으로 만들어졌지만,
 * host 값을 전혀 검증하지 않고 시스템 명령 문자열에 그대로 이어붙인다.
 * 예) host=127.0.0.1;whoami  또는  host=127.0.0.1 & whoami  처럼
 *     명령 구분자를 섞어 보내면 ping 대신(또는 ping과 함께) 다른 명령이 실행된다.
 *
 * 반드시 격리된 환경에서만 켜둔다. 인터넷에 노출하지 않는다.
 */
class DiagnosticsController
{
    public function ping(string $host): void
    {
        // 취약점의 핵심: 길이 제한도, 문자 제한도, escapeshellarg() 도 없다.
        $flag = stripos(PHP_OS, 'WIN') === 0 ? 'ping -n 1 ' : 'ping -c 1 ';
        $output = shell_exec($flag . $host . ' 2>&1');
        if ($output !== null) {
            // Windows 한국어 cmd 출력은 CP949라서 UTF-8로 바꿔야 json_encode가 깨지지 않는다.
            $converted = @mb_convert_encoding($output, 'UTF-8', 'CP949');
            if ($converted !== false) {
                $output = $converted;
            }
        }

        Response::json([
            'host'   => $host,
            'output' => (string) $output,
        ]);
    }
}