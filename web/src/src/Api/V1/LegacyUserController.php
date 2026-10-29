<?php
declare(strict_types=1);

namespace App\Api\V1;

use App\Core\HttpException;
use App\Core\Response;
use App\Repositories\UserRepository;

/**
 * [레거시 v1 — 의도된 취약점] 인가 부재로 인한 개인정보 탈취 (BOLA / IDOR)
 *
 * 진입점(public/api/v1/index.php)에서 JWT 서명·만료는 "검증"하지만,
 * 여기서는 "이 토큰의 주인(sub)이 요청한 {id}와 같은지"를 전혀 비교하지 않는다.
 * → 유효한 토큰만 있으면(= 아무 계정이나 로그인하면) 번호만 바꿔 남의 개인정보를 그대로 본다.
 *   (OWASP API Security Top 10 #1: Broken Object Level Authorization)
 *
 * v2의 UserController::me() 는 토큰의 sub 본인 정보만 돌려주므로 이 문제가 없다.
 *
 * 설계 메모: "v2 전환 때 지우지 않고 방치된 레거시"라는 시나리오.
 * Service 계층을 건너뛰고 Repository를 직접 호출한다 (v2의 계층 규칙을 지키지 않음).
 */
class LegacyUserController
{
    /** @var UserRepository */
    private $users;

    public function __construct(UserRepository $users)
    {
        $this->users = $users;
    }

    public function show(string $rawId): void
    {
        if (!ctype_digit($rawId)) {
            throw new HttpException(422, 'id는 숫자여야 합니다');
        }
        // 소유권 검사가 없다 — 토큰만 유효하면 자기 id가 아니어도 어떤 번호든 조회된다(BOLA).
        $user = $this->users->getPublicById((int) $rawId);
        if ($user === null) {
            throw new HttpException(404, '존재하지 않는 사용자입니다');
        }
        Response::json($user);
    }
}