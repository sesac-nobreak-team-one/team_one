<?php
declare(strict_types=1);

namespace App\Services;

use App\Core\Security;
use App\Repositories\UserRepository;

/**
 * 업무 규칙 (← app/services/user_service.py)
 * HTTP(상태 코드, 요청/응답)는 알지 못한다.
 */
class UserService
{
    /** @var UserRepository */
    private $users;
    /** @var Security */
    private $security;

    public function __construct(UserRepository $users, Security $security)
    {
        $this->users    = $users;
        $this->security = $security;
    }

    public function signup(string $name, string $email, string $password, ?string $phone, ?string $address): array
    {
        if ($this->users->getByEmail($email) !== null) {
            throw new EmailAlreadyExists();
        }

        try {
            $userId = $this->users->create(
                $name,
                $email,
                $phone,
                $address,
                $this->security->hashPassword($password)
            );
        } catch (\PDOException $e) {
            // 확인과 저장 사이에 같은 이메일이 들어온 경우 (UNIQUE 제약 위반)
            if (isset($e->errorInfo[1]) && (int) $e->errorInfo[1] === 1062) {
                throw new EmailAlreadyExists();
            }
            throw $e;
        }

        return ['id' => $userId, 'email' => $email];
    }

    /** 성공하면 토큰 문자열을 돌려준다. */
    public function login(string $email, string $password): string
    {
        $user = $this->users->getByEmail($email);
        // 이메일 없음과 비밀번호 틀림을 같은 예외로 처리
        if ($user === null || !$this->security->verifyPassword($password, $user['password_hash'])) {
            throw new InvalidCredentials();
        }
        return $this->security->createToken($user['id']);
    }

    /**
     * 추가: 내 정보 수정. 바꾼 뒤의 공개용 회원 정보를 돌려준다.
     * 누구의 정보를 바꿀지는 요청 본문이 아니라 토큰의 사용자($userId)로 정한다.
     */
    public function updateMe(int $userId, array $fields): array
    {
        $this->users->updateProfile($userId, $fields);
        return $this->users->getPublicById($userId);
    }
}
