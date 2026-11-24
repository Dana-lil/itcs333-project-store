<?php

declare(strict_types=1);

function auth_public_user(array $row): array
{
    return [
        'id'       => (int) $row['id'],
        'username' => (string) $row['username'],
        'is_admin' => (int) $row['is_admin'],
    ];
} //end function


function auth_find_by_username(string $username): ?array
{
    $stmt = db()->prepare(
        'SELECT id, username, password_hash, is_admin FROM users WHERE username = ?'
    );
    $stmt->execute([$username]);
    $row = $stmt->fetch();
    return $row === false ? null : $row;
} // end function 

$rest   = rtrim($GLOBALS['__route']['rest'] ?? '', '/');
$method = http_method();

switch ($rest) {
    default:
        send_error(404, 'NOT_FOUND');
}
