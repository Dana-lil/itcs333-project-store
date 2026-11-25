<?php

function auth_find_by_username($username)
{
    $stmt = db()->prepare("SELECT id, username, password_hash, is_admin FROM users WHERE username = ?");
    $stmt->execute([$username]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
} // end function

function auth_public_user($row)
{
    return [
        'id' => (int) $row['id'],
        'username' => $row['username'],
        'is_admin' => (int) $row['is_admin']
    ];
} //end function

function current_user()
{
    if (empty($_SESSION['user_id'])) {
        return null;
    } //end if
    $stmt = db()->prepare("SELECT id, username, is_admin FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        return null;
    } //end if
    return auth_public_user($row);
}//end function

function auth_register()
{
    $input = json_body();
$username = '';
    $password = '';
    $is_admin = 0;
    if (isset($input['username']) && is_string($input['username'])) {
        $username = trim($input['username']);
    }
    if (isset($input['password']) && is_string($input['password'])) {
        $password = $input['password'];
    }
    if (!empty($input['is_admin'])) {
        $is_admin = 1;
    }
     $fields = [];
    if ($username == '') {
        $fields['username'] = 'required';
    }
    if ($password == '') {
        $fields['password'] = 'required';
    }
    if (count($fields) > 0) {
        send_error(422, 'VALIDATION', ['fields' => $fields]);
    }
     if (auth_find_by_username($username)) {
        send_error(409, 'USERNAME_TAKEN');
    }

     try {
        $stmt = db()->prepare("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)");
        $stmt->execute([$username, password_hash($password, PASSWORD_DEFAULT), $is_admin]);
    }//end try
    
    catch (PDOException $e) {
        
        if (substr($e->getCode(), 0, 2) == '23') {
            send_error(409, 'USERNAME_TAKEN');
        }

        throw $e;
    }//end catch

     $user = auth_find_by_username($username);
    send_json(201, auth_public_user($user));
}//end function


function auth_login()
{
    $input = json_body();

    $username = '';
    $password = '';
    if (isset($input['username']) && is_string($input['username'])) {
        $username = trim($input['username']);
    }
    if (isset($input['password']) && is_string($input['password'])) {
        $password = $input['password'];
    }

    $user = false;
    if ($username != '') {
        $user = auth_find_by_username($username);
    }
     if (!$user || !password_verify($password, $user['password_hash'])) {
        send_error(401, 'INVALID_CREDENTIALS');
    }

    session_regenerate_id(true);
    $_SESSION['user_id'] = (int) $user['id'];
    $_SESSION['username'] = $user['username'];

    $result = auth_public_user($user);
    $result['token'] = session_id();
    send_json(200, $result);
}// end function


function auth_logout()
{
    $_SESSION = [];
    session_destroy();
    send_json(200, ['ok' => true]);
}//end function

function auth_me()
{
    $user = current_user();
    if (!$user) {
        send_error(401, 'AUTH_REQUIRED');
    }
    send_json(200, $user);
}// end functioon

$rest = rtrim($GLOBALS['__route']['rest'] ?? '', '/');
$method = http_method();

switch ($rest) {
    case '/register':
        if ($method != 'POST') {
            send_error(405, 'METHOD_NOT_ALLOWED');
        }
        auth_register();
        break;

    case '/login':
        if ($method != 'POST') {
            send_error(405, 'METHOD_NOT_ALLOWED');
        }
        auth_login();
        break;

    case '/logout':
        if ($method != 'POST') {
            send_error(405, 'METHOD_NOT_ALLOWED');
        }
        auth_logout();
        break;

    case '/me':
        if ($method != 'GET') {
            send_error(405, 'METHOD_NOT_ALLOWED');
        }
        auth_me();
        break;

    default:
        send_error(404, 'NOT_FOUND');
}// end switch