<?php
declare(strict_types=1);

namespace App\Repositories;

use PDO;

/**
 * SQL 실행만 담당 (← app/repositories/user_repository.py)
 * 업무 규칙(중복 확인 등)은 여기서 판단하지 않는다.
 * 모든 쿼리는 prepared statement — 문자열 이어붙이기 금지.
 */
class UserRepository
{
    /** @var PDO */
    private $db;

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    public function getByEmail(string $email): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT id, name, email, phone, address, password_hash
               FROM users WHERE email = :email'
        );
        $stmt->execute(['email' => $email]);
        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        $row['id'] = (int) $row['id'];
        return $row;
    }

    /** password_hash를 뺀 공개용 회원 정보 */
    public function getPublicById(int $userId): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT id, name, email, phone, address FROM users WHERE id = :id'
        );
        $stmt->bindValue(':id', $userId, PDO::PARAM_INT);
        $stmt->execute();
        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        $row['id'] = (int) $row['id'];
        return $row;
    }

    public function create(string $name, string $email, ?string $phone, ?string $address, string $passwordHash): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO users (name, email, phone, address, password_hash)
             VALUES (:name, :email, :phone, :address, :pw)'
        );
        $stmt->execute([
            'name'    => $name,
            'email'   => $email,
            'phone'   => $phone,
            'address' => $address,
            'pw'      => $passwordHash,
        ]);
        return (int) $this->db->lastInsertId();
    }

    /* ===== 추가: 내 정보 수정 ===== */

    /** 수정할 수 있는 컬럼. 컬럼 이름은 바인딩할 수 없어서 이 목록에 있는 것만 SQL 에 들어간다 */
    const EDITABLE_COLUMNS = ['name', 'phone', 'address'];

    /** $fields 에 들어 있는 항목만 바꾼다. 없는 항목은 그대로 둔다. */
    public function updateProfile(int $userId, array $fields): void
    {
        $sets = [];
        foreach (self::EDITABLE_COLUMNS as $col) {
            if (array_key_exists($col, $fields)) {
                $sets[] = $col . ' = :' . $col;
            }
        }
        if ($sets === []) {
            return;
        }

        $stmt = $this->db->prepare('UPDATE users SET ' . implode(', ', $sets) . ' WHERE id = :id');
        foreach (self::EDITABLE_COLUMNS as $col) {
            if (array_key_exists($col, $fields)) {
                $value = $fields[$col];
                $stmt->bindValue(':' . $col, $value, $value === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
            }
        }
        $stmt->bindValue(':id', $userId, PDO::PARAM_INT);
        $stmt->execute();
    }
}
