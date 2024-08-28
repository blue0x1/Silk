<?php

/**
 * Silk Shoutbox
 * 
 * © 2024 blue0x1 (Chokri Hammedi). All rights reserved.
 *
 * This code is part of the Silk Shoutbox project.
 * Unauthorized copying of this file, via any medium, is strictly prohibited.
 * Proprietary and confidential.
 * 
 * Written by blue0x1 (Chokri Hammedi) https://github.com/blue0x1  , August 2024.
 */

ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? '1' : '0');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.gc_maxlifetime', 1440);
ini_set('session.cookie_lifetime', 0);

session_start();

if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
     createCsrfToken();
}



define('DATA_FILE', 'data.json');
define('DEFAULT_ADMIN_KEY', 'admin123'); // default admin key
define('ENCRYPTION_KEY', 'b14ca5898a4e4133bbce2ea2315a1916');   // Encryption Key Must be changed
define('ENCRYPTION_IV', '1234567891011121');

function encryptData($data) {
    return openssl_encrypt($data, 'AES-256-CBC', ENCRYPTION_KEY, 0, ENCRYPTION_IV);
}

function decryptData($data) {
    return openssl_decrypt($data, 'AES-256-CBC', ENCRYPTION_KEY, 0, ENCRYPTION_IV);
}

function getData() {
    if (!file_exists(DATA_FILE)) {
        $defaultData = [
            'messages' => [],
            'key' => '',
            'max_users' => 20,
            'key_status' => 0,
            'title' => 'Silk Shoutbox',
            'admin_key' => DEFAULT_ADMIN_KEY,
            'giphy_api_key' => '',
            'users' => [
                1 => ['uid' => 1, 'username' => 'Admin', 'icon' => 'fas fa-crown'],
            ],
            'theme' => [
                'background_color' => '#1a1a1a',
                'primary_color' => '#ffd700',
                'secondary_color' => '#e6b800',
                'input_bg_color' => '#333',
                'title_bg_color' => '#2a2a2a',
                'admin_bg_color' => '#ca1d1d14',
                'admin_text_color' => '#ffffff',
            ],
            'next_uid' => 2
        ];
        file_put_contents(DATA_FILE, encryptData(json_encode($defaultData)));
    }

    $encryptedData = file_get_contents(DATA_FILE);
    $jsonData = decryptData($encryptedData);

    if ($jsonData === false) {
        exit('Data file is encrypted and cannot be decrypted.');
    }

    $data = json_decode($jsonData, true);

     if (!isset($data['max_users']) || $data['max_users'] > 999) {
        $data['max_users'] = 999;
    }

    return $data;
}


function saveData($data) {
    $encryptedData = encryptData(json_encode($data));
    file_put_contents(DATA_FILE, $encryptedData);
}

function getNextUID(&$data) {
    $nextUid = $data['next_uid'];
    $data['next_uid']++;
    return $nextUid;
}

function generateRandomUsername() {
    return 'user_' . rand(100, 999);
}

function checkAuthenticationRateLimit() {
    $ip = $_SERVER['REMOTE_ADDR'];
    $currentTime = time();
    $lockoutDuration = 60;
    $maxAttempts = 5;

    if (!isset($_SESSION['auth_attempts'][$ip])) {
        $_SESSION['auth_attempts'][$ip] = ['last_attempt_time' => $currentTime, 'attempt_count' => 1];
    } else {
        if (($currentTime - $_SESSION['auth_attempts'][$ip]['last_attempt_time']) < $lockoutDuration) {
            $_SESSION['auth_attempts'][$ip]['attempt_count']++;
            if ($_SESSION['auth_attempts'][$ip]['attempt_count'] > $maxAttempts) {
                http_response_code(429); // Too Many Requests
                die(json_encode(['error' => 'Too many authentication attempts. Please try again later.']));
            }
        } else {
             $_SESSION['auth_attempts'][$ip] = ['last_attempt_time' => $currentTime, 'attempt_count' => 1];
        }
    }
}

function createCsrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken($token) {
    return isset($_SESSION['csrf_token']) && $_SESSION['csrf_token'] === $token;
}


function sanitizeMessage($message) {
   $permittedTags = '<img>';
    $permittedAttributes = ['src', 'alt', 'class'];

    if (strpos($message, 'giphy-gif') !== false) {
        return $message;
    }

    $message = strip_tags($message, $permittedTags);

    return preg_replace_callback('/<img(.*?)>/', function($matches) use ($permittedAttributes) {
        $attributeString = $matches[1];
        preg_match_all('/(\w+)=("[^"]*"|\'[^\']*\'|[^\s>]*)/', $attributeString, $attributePairs, PREG_SET_ORDER);
        $filteredAttributes = '';

        foreach ($attributePairs as $attribute) {
            $attributeName = strtolower($attribute[1]);
            if (in_array($attributeName, $permittedAttributes)) {
                $filteredAttributes .= " $attributeName=" . htmlspecialchars($attribute[2], ENT_QUOTES, 'UTF-8');
            }
        }

        return '<img' . $filteredAttributes . '>';
    }, $message);
}

function sendMessage($message, $uid, $username, $icon, $isAdmin) {
    $data = getData();

     $pattern = '/@([a-zA-Z0-9_]+)/';

    $message = preg_replace_callback($pattern, function ($matches) use ($data) {
        $mentionedUsername = $matches[1];

        foreach ($data['users'] as $user) {
            if (strcasecmp($user['username'], $mentionedUsername) === 0) {
                return '<span class="mention">@' . htmlspecialchars($mentionedUsername) . '</span>';
            }
        }

        return $matches[0];
    }, $message);


     if ($uid == 1) {
         $icon = $data['users'][$uid]['icon'] ?? 'fas fa-crown';
    } else {
         $icon = $data['users'][$uid]['icon'] ?? 'fas fa-user';
    }

     $sanitizedMessage = sanitizeMessage($message);

    $msg = [
        'user' => $username,
        'icon' => $icon,
        'message' => $sanitizedMessage,
        'timestamp' => date('h:i A'),
        'uid' => $uid,
        'is_admin' => $isAdmin
    ];

    $data['messages'][] = $msg;
    saveData($data);

    return $msg;
}

if (isset($_GET['search_users']) && isset($_GET['prefix'])) {
    if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
        $prefix = trim($_GET['prefix']);

         if (!preg_match('/^[a-zA-Z0-9_]{1,20}$/', $prefix)) {
            echo json_encode(['error' => 'Invalid input.']);
            exit;
        }
         $prefix = htmlspecialchars($prefix, ENT_QUOTES, 'UTF-8');
        $data = getData();
        $usernames = array_column($data['users'], 'username');
        $matchingUsers = array_filter($usernames, function($username) use ($prefix) {
            return stripos($username, $prefix) === 0;
        });

        echo json_encode(array_values($matchingUsers));
    } else {
        http_response_code(403);
        echo json_encode(['error' => 'Unauthorized']);
    }
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $data = getData();

    if (isset($_POST['authenticate'])) {
        checkAuthenticationRateLimit();

        if (count($data['users']) >= $data['max_users']) {
    echo json_encode(['error' => 'User limit reached']);
    exit;
}


        if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
            die('Security error: CSRF token mismatch.');
        }

        $key = htmlspecialchars(trim($_POST['key']));

        if ($key === $data['admin_key']) {
            unset($_SESSION['rate_limit'][$_SERVER['REMOTE_ADDR']]);
            $_SESSION['is_admin'] = true;
            $_SESSION['uid'] = 1;
            $_SESSION['username'] = $data['users'][1]['username'];
            $_SESSION['icon'] = $data['users'][1]['icon'] ?? 'fas fa-crown';
            $_SESSION['authenticated'] = true;
            setcookie('chat_key', $key, [
                'expires' => time() + 3600,
                'path' => '/',
                'httponly' => true,
                'samesite' => 'Strict'
            ]);

            echo json_encode(['admin' => true, 'username' => $data['users'][1]['username']]);
            exit;
        } elseif (!empty($data['key']) && $key === $data['key']) {
            unset($_SESSION['rate_limit'][$_SERVER['REMOTE_ADDR']]);
            if (!isset($_SESSION['username'])) {


                 if (count($data['users']) >= $data['max_users']) {
            echo json_encode(['error' => 'User limit reached']);
            exit;
        }

                $randomUsername = generateRandomUsername();
                $uid = getNextUID($data);
                $data['users'][$uid] = [
                    'uid' => $uid,
                    'username' => $randomUsername,
                    'icon' => $data['users']['default']['icon'] ?? 'fas fa-user'
                ];
                saveData($data);

                $_SESSION['username'] = $randomUsername;
                $_SESSION['uid'] = $uid;
            }
            $_SESSION['is_admin'] = false;
            $_SESSION['authenticated'] = true;
            $_SESSION['icon'] = $data['users'][$_SESSION['uid']]['icon'] ?? 'fas fa-user';

            setcookie('chat_key', $key, [
                'expires' => time() + 3600,
                'path' => '/',
                'httponly' => true,
                'samesite' => 'Strict'
            ]);

            $data['key_status'] = 0;
            saveData($data);

            echo json_encode(['authenticated' => true, 'username' => $_SESSION['username']]);
        } else {
            echo json_encode(['error' => 'Invalid key']);
        }
        exit;
    }

    if (isset($_POST['send']) && isset($_SESSION['authenticated'])) {
        $message = $_POST['message'];
        $uid = $_SESSION['uid'];
        $username = $_SESSION['username'];
        $icon = $data['users'][$uid]['icon'] ?? 'fas fa-user';
        $isAdmin = $_SESSION['is_admin'] ?? false;

        $msg = sendMessage($message, $uid, $username, $icon, $isAdmin);

        echo json_encode($msg);
        exit;
    }

    if (isset($_POST['fetch']) && isset($_SESSION['authenticated'])) {
        $messages = $data['messages'] ?? [];
        echo json_encode($messages);
        exit;
    }

    if (isset($_POST['saveSettings'])) {
        $response = ['success' => false];


        if (!isset($_POST['csrf_token']) || !validateCsrfToken($_POST['csrf_token'])) {
        echo json_encode(['error' => 'Security error: CSRF token mismatch.']);
        exit;
    }

        if (isset($_SESSION['authenticated'])) {
            $newUsername = htmlspecialchars($_POST['username'] ?? $_SESSION['username']);
            $newTitle = htmlspecialchars($_POST['title'] ?? $data['title']);
            $newAdminKey = htmlspecialchars($_POST['adminKey'] ?? $data['admin_key']);
            $icon = htmlspecialchars($_POST['icon'] ?? ($newUsername === $data['users'][1]['username'] ? ($data['users'][1]['icon'] ?? 'fas fa-crown') : $data['users'][$_SESSION['uid']]['icon']));
            $giphyApiKey = htmlspecialchars($_POST['giphyApiKey'] ?? '');

            if (preg_match('/\s/', $newUsername)) {
                echo json_encode(['error' => "Username cannot contain spaces."]);
                exit;
            }

            if (strlen($newUsername) > 20) {
                echo json_encode(['error' => "Username cannot exceed 20 characters."]);
                exit;
            }

            if ($newUsername !== $_SESSION['username'] && preg_match('/\badmin\b/i', $newUsername) && !$_SESSION['is_admin']) {
                echo json_encode(['error' => 'The username cannot contain any variation of "admin".']);
                exit;
            }

            $_SESSION['username'] = $newUsername;
            $_SESSION['icon'] = $icon;

            if ($_SESSION['is_admin']) {
                $data['title'] = $newTitle;
                $data['admin_key'] = $newAdminKey;
                $data['users'][1]['username'] = $newUsername;

                 if (isset($_POST['maxUsers']) && !preg_match('/^\d+$/', $_POST['maxUsers'])) {
            echo json_encode(['error' => 'Max Users must be a number.']);
            exit;
        }


                $data['max_users'] = intval($_POST['maxUsers']) > 0 ? intval($_POST['maxUsers']) : $data['max_users'];


                if (isset($_POST['icon']) && $_POST['icon'] !== '') {
                    $data['users'][1]['icon'] = htmlspecialchars($_POST['icon']);
                }

                $data['giphy_api_key'] = $giphyApiKey;
            } else {
                $data['users'][$_SESSION['uid']]['username'] = $newUsername;
                $data['users'][$_SESSION['uid']]['icon'] = $icon ?: $data['users'][$_SESSION['uid']]['icon'];
            }

            saveData($data);

            $response['success'] = true;
            $response['newUsername'] = $newUsername;
            $response['icon'] = $icon;

            if ($_SESSION['is_admin']) {
                $response['newTitle'] = $newTitle;
                $response['newAdminKey'] = $newAdminKey;
                 $response['maxUsers'] = $data['max_users'];
            }
        }

        echo json_encode($response);
        exit;
    }

    if (isset($_POST['checkKey'])) {
        if (!$_SESSION['authenticated']) {
            echo json_encode(['error' => 'User not authenticated']);
            exit;
        }

        if (($data['key_status'] == 1 && $_SESSION['key'] !== $data['key']) || empty($data['key'])) {
            if (!$_SESSION['is_admin']) {
                session_destroy();
                setcookie('chat_key', '', time() - 3600, '/');
            }
            echo json_encode(['key_changed' => true]);
        } else {
            echo json_encode(['key_valid' => true]);
        }
        exit;
    }

    if (isset($_POST['saveThemeSettings']) && $_SESSION['is_admin']) {

         if (!isset($_POST['csrf_token']) || !validateCsrfToken($_POST['csrf_token'])) {
        echo json_encode(['error' => 'Security error: CSRF token mismatch.']);
        exit;
    }



        $data['theme']['background_color'] = htmlspecialchars($_POST['backgroundColorInput'] ?? $data['theme']['background_color'], ENT_QUOTES, 'UTF-8');
        $data['theme']['primary_color'] = htmlspecialchars($_POST['primaryColorInput'] ?? $data['theme']['primary_color'], ENT_QUOTES, 'UTF-8');
        $data['theme']['secondary_color'] = htmlspecialchars($_POST['secondaryColorInput'] ?? $data['theme']['secondary_color'], ENT_QUOTES, 'UTF-8');
        $data['theme']['input_bg_color'] = htmlspecialchars($_POST['inputBgColorInput'] ?? $data['theme']['input_bg_color'], ENT_QUOTES, 'UTF-8');
        $data['theme']['title_bg_color'] = htmlspecialchars($_POST['titleBgColorInput'] ?? $data['theme']['title_bg_color'], ENT_QUOTES, 'UTF-8');
        $data['theme']['admin_bg_color'] = htmlspecialchars($_POST['adminBgColorInput'] ?? $data['theme']['admin_bg_color'], ENT_QUOTES, 'UTF-8');
        $data['theme']['admin_text_color'] = htmlspecialchars($_POST['adminTextColorInput'] ?? $data['theme']['admin_text_color'], ENT_QUOTES, 'UTF-8');

        saveData($data);

        header("Location: " . $_SERVER['REQUEST_URI']);
        exit;
    }

    if (isset($_POST['updateSessionIcon']) && isset($_SESSION['authenticated'])) {
    $newIcon = htmlspecialchars($_POST['icon']);
    $_SESSION['icon'] = $newIcon;

    echo json_encode(['success' => true]);
    exit;
}

    if (isset($_POST['generate']) && $_SESSION['is_admin']) {
        $newKey = bin2hex(random_bytes(16));
        $_SESSION['generated_key'] = $newKey;
        $data['key'] = $newKey;
        $data['key_status'] = 1;
        saveData($data);
        echo json_encode(['key' => $newKey]);
        exit;
    }

    if (isset($_POST['resetTheme']) && $_SESSION['is_admin']) {
        $data['theme'] = [
            'background_color' => '#1a1a1a',
            'primary_color' => '#ffd700',
            'secondary_color' => '#e6b800',
            'input_bg_color' => '#333',
            'title_bg_color' => '#2a2a2a',
            'admin_bg_color' => '#ca1d1d14',
            'admin_text_color' => '#ffffff',
        ];

        saveData($data);
        echo json_encode(['themeReset' => true]);
        exit;
    }

        if (isset($_POST['purge']) && $_SESSION['is_admin']) {
        $currentData = getData();
        $currentAdminKey = $currentData['admin_key'];

        $data = [
            'messages' => [],
            'key' => '',
            'key_status' => 0,
            'title' => 'Silk Shoutbox',
            'admin_key' => $currentAdminKey,
            'giphy_api_key' => '',
            'users' => [
                1 => ['uid' => 1, 'username' => 'Admin', 'icon' => 'fas fa-crown'],
            ],
            'theme' => [
                'background_color' => '#1a1a1a',
                'primary_color' => '#ffd700',
                'secondary_color' => '#e6b800',
                'input_bg_color' => '#333',
                'title_bg_color' => '#2a2a2a',
                'admin_bg_color' => '#ca1d1d14',
                'admin_text_color' => '#ffffff',
            ],
            'max_users' => 999,
        ];

        saveData($data);

        session_destroy();
        setcookie('chat_key', '', time() - 3600, '/');
        $_SESSION['is_admin'] = true;
        echo json_encode(['purged' => true]);
        exit;
    }

    if (isset($_POST['logout'])) {
        session_unset();
        session_destroy();
        setcookie('chat_key', '', [
            'expires' => time() - 3600,
            'path' => '/',
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
        echo json_encode(['success' => true]);
        exit;
    }

    echo json_encode(['error' => 'Invalid request']);
    exit;
}



$authenticated = isset($_SESSION['authenticated']) && $_SESSION['authenticated'];
$isAdmin = isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true;
$data = getData();
$title = $data['title'] ?? 'Silk Shoutbox';
$adminKey = $data['admin_key'] ?? DEFAULT_ADMIN_KEY;
$currentKey = $_SESSION['generated_key'] ?? $data['key'] ?? '';


?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">

    <title><?php echo $title; ?></title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/uikit@3.21.9/dist/css/uikit.min.css" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">

    <style>
     :root {
    --background-color: <?php echo $data['theme']['background_color'] ?? '#1a1a1a'; ?>;
    --primary-color: <?php echo $data['theme']['primary_color'] ?? '#ffd700'; ?>;
    --secondary-color: <?php echo $data['theme']['secondary_color'] ?? '#e6b800'; ?>;
    --input-bg-color: <?php echo $data['theme']['input_bg_color'] ?? '#333'; ?>;
    --title-bg-color: <?php echo $data['theme']['title_bg_color'] ?? '#2a2a2a'; ?>;
    --admin-bg-color: <?php echo $data['theme']['admin_bg_color'] ?? '#ca1d1d14'; ?>;
    --admin-text-color: <?php echo $data['theme']['admin_text_color'] ?? '#ffffff'; ?>;
}

body {
    background-color: var(--background-color);
    color: var(--primary-color);
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    height: 100vh;
    margin: 0;
    display: flex;
    flex-direction: column;
}

.container {
    display: flex;
    flex-direction: row;
    width: 100%;
    height: 100%;
}

.left-half, .right-half {
    width: 50%;
    height: 100%;
    display: flex;
    justify-content: center;
    align-items: center;
}

.left-half {
    background-color: var(--title-bg-color);
}

.right-half {
    background-color: var(--background-color);
    position: relative;
    flex-direction: column;
}

.title {
    font-size: 3em;
    text-align: center;
    color: var(--primary-color);
    font-weight: bold;
}

.auth-container {
    text-align: center;
    display: flex;
    justify-content: center;
    align-items: center;
    <?php if ($authenticated) echo 'display: none;'; ?>
}

.auth-container input {
    background-color: var(--input-bg-color);
    color: var(--primary-color);
    border-radius: 8px;
    border: 1px solid var(--primary-color);
    padding: 12px;
    width: 70%;
    margin-right: 10px;
    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.6);
}

.auth-container button {
    background-color: var(--primary-color);
    font-weight: 600;
    color: var(--background-color);
    border-radius: 8px;
    border: none;
    padding: 12px 20px;
    cursor: pointer;
    transition: background-color 0.3s, transform 0.3s;
}

.auth-container button:hover {
    background-color: var(--secondary-color);
    transform: translateY(-2px);
}

 #backgroundColorInput, #primaryColorInput, #secondaryColorInput, #inputBgColorInput, #titleBgColorInput, #adminBgColorInput, #adminTextColorInput {

 max-width: 100%;
  width: 100%;
  border: 0 none;
  padding: 0 10px!important;
  background: transparent!important;
  color: #666;
  border: 1px solid transparent!important;
  transition: .2s ease-in-out;
    transition-property: all;
  transition-property: color,background-color,border;

  }


#chatContainer {
    display: <?php echo $authenticated ? 'flex' : 'none'; ?>;
    width: 100%;
    height: 80%;
    padding: 20px;
    box-sizing: border-box;
    flex-direction: column;
    justify-content: space-between;
}

#messages {
    flex-grow: 1;
    overflow-y: auto;
    padding: 10px;
    background-color: var(--background-color);
    border-radius: 8px;
    margin-bottom: 10px;
    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.6);
}

.message {
    margin: 5px 0;
    padding: 5px 10px;
    border-radius: 5px;
    background-color: var(--input-bg-color);
    color: var(--primary-color);
    display: flex;
    flex-direction: column;
}

.message img {
    margin-top: 5px;
    max-width: 100%;
    border-radius: 8px;
    width: 200px;
    height: 200px;
}

.admin-message {
    background-color: var(--admin-bg-color);
    color: var(--admin-text-color);
}

.input-group {
    display: flex;
    align-items: center;
    background-color: var(--input-bg-color);
    padding: 10px;
    border-radius: 8px;
    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.6);
}

.uk-flex-between > * {
    margin-left: 10px;
}

#messageInput,
#keyInput,
#usernameInput,
#titleInput,
#adminKeyInput,
#giphyApiKeyInput,
#encryptionKeyInput,
#encryptionIvInput {
    font-size: 16px;


}



#icons {


margin-bottom: -25px;
padding: 5px 20px;

}

@media (max-width: 768px) {
    #icons {
        float: left;
        margin-right: 5px;
    }
    #sendMessageButton {
        float: right;
        width: 75%;
        padding: 10px 15px;
    }
}

#maxUsersInput{

    width: 200px;
}

#messageInput, #titleInput,  #usernameInput, #adminKeyInput, #giphyApiKeyInput, #encryptionKeyInput, #encryptionIvInput, #maxUsersInput {
    background-color: var(--input-bg-color);
    color: var(--primary-color);
    border-radius: 8px;
    border: none;
    padding: 10px;
    flex-grow: 1;
    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.6);
}

#sendMessageButton {
    background-color: var(--primary-color);
    color: var(--background-color);
    border-radius: 8px;
    border: none;
    padding: 5px 20px;
    cursor: pointer;
    margin-left: 10px;
    transition: background-color 0.3s, transform 0.3s;
}

#sendMessageButton:hover {
    background-color: var(--secondary-color);
    transform: translateY(-2px);
}

#adminControls {
    display: <?php echo $isAdmin ? 'block' : 'none'; ?>;
    margin-top: 10px;
    text-align: center;
}

.uk-alert {
    background-color: var(--input-bg-color);
    color: var(--primary-color);
    border-radius: 8px;
    padding: 10px;
    margin-top: 10px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.4);
}

#alertBox {
    margin-top: 10px;
    padding: 10px;
    font-weight: bold;
    text-align: center;
    background-color: var(--input-bg-color);
    color: var(--primary-color);
    border-radius: 8px;
    display: none;
}

.key-display {
    font-size: 1.2em;
    color: var(--primary-color);
    padding: 10px;
    background-color: var(--title-bg-color);
    border-radius: 8px;
    margin-top: 10px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.4);
    text-align: center;
    <?php if (!$isAdmin || empty($currentKey)) echo 'display: none;'; ?>
}

#settingsButtonContainer {
    position: absolute;
    top: 20px;
    right: 20px;
    display: <?php echo $authenticated ? 'block' : 'none'; ?>;
}

#settingsButton {
    background-color: var(--primary-color);
    color: var(--background-color);
    border-radius: 8px;
    border: none;
    padding: 10px 20px;
    cursor: pointer;
    transition: background-color 0.3s, transform 0.3s;
}

#settingsButton:hover {
    background-color: var(--secondary-color);
    transform: translateY(-2px);
}

@media (max-width: 768px) {
    .left-half {
        height: <?php echo $authenticated ? '10%!important' : '40%!important'; ?>;
    }
    .right-half {
        height: <?php echo $authenticated ? '90%!important' : '60%!important'; ?>;
    }
    .container {
        flex-direction: column;
    }
    .left-half, .right-half {
        width: 100%;
        height: 50%;
    }
    .title {
        font-size: 2em;
    }
    .auth-container input, .auth-container button {
        width: 100%;
        margin: 5px 2px;
    }
    .input-group {
        flex-direction: column;
        align-items: stretch;
    }
    #icons {
        float: left;
    }
    #messageInput {
        margin-bottom: 7px;
    }

    .key-display {
        font-size: 1em;
        margin-top: 5px;
        padding: 5px;
    }
}

.uk-modal-dialog {
    background-color: var(--background-color);
    color: var(--primary-color);
    border-radius: 8px;
    padding: 20px;
}

.uk-modal-title {
    color: var(--primary-color);
}

.uk-form-label {
    font-weight: 600;
    opacity: 80%;
    color: var(--primary-color);
}

.uk-tab > .uk-active > a {
    color: var(--primary-color);
    border-color: var(--primary-color);
}


.uk-button-danger {
  background-color: #550615;
}

.uk-button-default {
    background-color: transparent;
    color: var(--primary-color);
    border: 1px solid var(--primary-color);
}

.uk-tab > li > a {
    color: var(--primary-color);
}

.uk-button-primary {
    background-color: var(--primary-color);
    color: var(--background-color);
    border-radius: 8px;
    border: none;
    padding: 1px 20px;
    cursor: pointer;
    transition: background-color 0.3s, transform 0.3s;
}

.uk-button-primary:hover {
    background-color: var(--secondary-color);
    transform: translateY(-2px);
}

.uk-dropdown {
    background: var(--background-color);
    border: 1px solid var(--primary-color);
    border-radius: 8px;
    padding: 10px;
    width: 100%;
}

.icon-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    grid-gap: 10px;
    padding: 10px;
    background-color: var(--background-color);
    border-radius: 8px;
}

.icon-grid i {
    font-size: 24px;
    color: var(--primary-color);
    cursor: pointer;
    transition: transform 0.2s, color 0.2s;
    width: 40px;
    height: 40px;
    line-height: 40px;
    text-align: center;
    display: inline-block;
}

.icon-grid i:hover {
    transform: scale(1.2);
    color: var(--secondary-color);
    background-color: var(--input-bg-color);
    border-radius: 50%;
}

#gifSearch {
    background-color: var(--input-bg-color);
    color: var(--primary-color);
    border-radius: 8px;
    border: 1px solid var(--primary-color);
    padding: 10px;
    width: 94%;
    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.6);
    margin-bottom: 10px;
}

#gifSearch::placeholder {
    color: var(--primary-color);
    opacity: 0.7;
}

#gifContainer {
    max-height: 150px;
    overflow-y: auto;
    margin-top: 10px;
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-start;
}

#gifContainer img {
    width: 100px;
    margin: 5px;
    cursor: pointer;
}

#gifContainer img:hover {
    border: 2px solid var(--primary-color);
}

.timestamp {
    font-size: 0.8em;
    color: #888;
    margin-top: 5px;
    float: right;
}

.icon-grid-compact {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    grid-gap: 5px;
    padding: 10px;
    background-color: var(--background-color);
    border-radius: 8px;
    width: 50%;
}

.icon-grid-compact i {
    font-size: 24px;
    color: var(--primary-color);
    cursor: pointer;
    transition: transform 0.2s, color 0.2s;
    width: 40px;
    height: 40px;
    line-height: 40px;
    text-align: center;
    display: inline-block;
}

.icon-grid-compact i:hover {
    transform: scale(1.2);
    color: var(--secondary-color);
    background-color: var(--input-bg-color);
    border-radius: 50%;
}

#messages i {
    color: var(--primary-color);
}


 #messages i.fa-heart {
    color: #ff69b4;
}

#messages i.fa-dragon {
    color: #ff4500;
}

#messages i.fa-star {
    color: #ffd700;
}

#messages i.fa-heart {
    color: #ff69b4;
}

#messages i.fa-smile {
    color: #ffa500;
}

#messages i.fa-robot {
    color: #808080;
}

#messages i.fa-music {
    color: #1e90ff;
}

#messages i.fa-chess-king {
    color: #8b4513;
}

#messages i.fa-gem {
    color: #daa520;
}

#messages i.fa-frog {
    color: #32cd32;
}

#messages i.fa-bell {
    color: #ff6347;
}

#messages i.fa-coffee {
    color: #6b4423;
}

#messages i.fa-leaf {
    color: #228b22;
}

#messages i.fa-fire {
    color: #ff4500;
}

#messages i.fa-ghost {
    color: #708090;
}

#messages i.fa-bolt {
    color: #ffff00;
}

#messages i.fa-hat-wizard {
    color: #9932cc;
}

#messages i.fa-anchor {
    color: #4682b4;
}

#messages i.fa-skull {
    color: #a9a9a9;
}

#messages i.fa-spider {
    color: #2f4f4f;
}

#messages i.fa-snowflake {
    color: #00bfff;
}

#messages i.fa-rocket {
    color: #ff4500;
}

#messages i.fa-bug {
    color: #8b0000;
}

#messages i.fa-hat-cowboy {
    color: #8b4513;
}

#messages i.fa-cat {
    color: #dda0dd;
}

#messages i.fa-skull-crossbones {
    color: #696969;
}

#messages i.fa-paw {
    color: #bc8f8f;
}

#messages i.fa-candy-cane {
    color: #ff1493;
}

#messages i.fa-globe {
    color: #00ced1;
}

#settingsError {
    margin-top: 10px;
    padding: 10px;
    font-weight: bold;
    text-align: center;
    background-color: var(--input-bg-color);
    color: var(--primary-color);
    border-radius: 8px;
    display: none;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.4);
    margin-bottom: 10px;
}

.uk-modal-title {
  font-size: 1.5rem; }


.mention {
     background-color: rgba(255, 215, 0, 0.15);
    color: #000;
    font-weight: bold;
    padding: 0px 0.5px;
    border-radius: 3px;
    display: inline-block;
}




#mentionDropdown {
    display: none;
    position: absolute;
    width: 250px!important;
    max-height: 150px;
    overflow-y: auto;
    background-color: #333;
    border: 1px solid #ffd700;
    border-radius: 5px;
    z-index: 1000;
    left: 10px!important;
    top: 100%;
    transform: translateY(5px);

}

#mentionDropdown ul {
    list-style: none;
    padding: 0;
    margin: 0;
}

#mentionDropdown ul li {
    padding: 10px;
    color: #ffd700;
    cursor: pointer;
}

#mentionDropdown ul li:hover {
    background-color: #444;
}

.uk-open #mentionDropdown {
    display: block;
    position: fixed;
}




    </style>
</head>
<body>
<div class="container">
    <div class="left-half">
        <div class="title"><?php echo $title; ?></div>
    </div>

    <div class="right-half">
        <?php if ($authenticated): ?>
            <div id="settingsButtonContainer">
                    <button id="logoutButton" class="uk-button uk-button-default uk-button-small" onclick="logout()">
    <i class="fas fa-sign-out-alt"></i> Logout
</button>
                <button id="settingsButton"><i class="fas fa-cog"></i> Settings</button>
            </div>
        <?php endif; ?>
    <div class="auth-container" id="authContainer">
    <input type="hidden" name="csrf_token" value="<?php echo createCsrfToken(); ?>">
    <input type="password" id="keyInput" placeholder="Enter your key..." required>
    <button type="button" onclick="authenticate()">Authenticate</button>



</div>

<div id="authError" uk-alert class="uk-alert-danger" style="display: none; margin-top: 10px;"> <p id="authErrorMessage"></p> </div>



      <?php if ($authenticated): ?>
    <div id="chatContainer">
        <div id="messages"></div>
        <div class="input-group">
            <input class="uk-input" type="text" id="messageInput" placeholder="Type your message...">

            <div id="mentionDropdown" class="uk-dropdown" uk-dropdown="mode: click; pos: bottom-left">
        <ul id="mentionList" class="uk-list"></ul>
    </div>


            <div class="uk-width-auto uk-flex uk-flex-between uk-flex-nowrap">
                <div class="icon-dropdown-wrapper">
                    <button id="icons" class="uk-button uk-button-default icon-button" type="button">
                        <i class="fas fa-smile"></i>
                    </button>

                    <div uk-dropdown="pos: top-justify" class="uk-dropdown">
                        <ul uk-tab>
                            <li><a href="#">Icons</a></li>
                            <?php if (!empty($data['giphy_api_key'])): ?>
                                <li><a href="#">GIFs</a></li>
                            <?php endif; ?>
                        </ul>

                        <ul class="uk-switcher uk-margin">
                            <li>
                                <div class="icon-grid-compact">
                                    <i class="fas fa-smile" data-icon=":)" title=":)" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-smile-wink" data-icon=";)" title=";)" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-laugh" data-icon=":D" title=":D" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-frown" data-icon=":(" title=":(" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-grin-tongue" data-icon=":P" title=":P" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-surprise" data-icon=":O" title=":O" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-meh" data-icon=":|" title=":|" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-grin-squint" data-icon="XD" title="XD" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-kiss" data-icon=":*" title=":*" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-angry" data-icon=":@" title=":@" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-meh-rolling-eyes" data-icon=":/" title=":/" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-heart" data-icon=":heart:" title=":heart:" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-flushed" data-icon=":$" title=":$" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-ghost" data-icon="^_^" title="^_^" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-dizzy" data-icon="D:" title="D:" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-glasses" data-icon="8-)" title="8-)" onclick="selectIcon(this)"></i>
                                    <i class="fas fa-sad-tear" data-icon="X(" title="X(" onclick="selectIcon(this)"></i>
                                </div>
                            </li>

                            <?php if (!empty($data['giphy_api_key'])): ?>
                                <li>
                                    <div id="gifSection">
                                        <input type="text" id="gifSearch" placeholder="Search GIFs..." oninput="fetchGifs(this.value)">
                                        <div id="gifContainer"></div>
                                    </div>
                                </li>
                            <?php endif; ?>
                        </ul>
                    </div>
                </div>

                <button id="sendMessageButton" class="uk-button uk-button-primary send-button" onclick="sendMessage()">Send</button>
            </div>
        </div>

        <div id="adminControls" style="display: <?php echo $isAdmin ? 'block' : 'none'; ?>;">
            <button class="uk-button uk-button-secondary" onclick="generateKey()">Generate New Key</button>
        </div>

        <div id="alertBox"></div>
        <div id="keyContainer" class="key-display">Key: <?php echo $currentKey; ?></div>
    </div>
<?php endif; ?>

    </div>
</div>


<?php if ($authenticated): ?>
    <div id="settingsModal" uk-modal>
        <div class="uk-modal-dialog uk-modal-body">
            <h2 class="uk-modal-title"><strong>Settings</strong></h2>
            <ul uk-tab>
                <li><a href="#">General</a></li>
                <?php if ($isAdmin) : ?>
                    <li><a href="#">Security</a></li>
                    <li><a href="#">Theme</a></li>
                <?php endif; ?>
            </ul>

            <ul class="uk-switcher uk-margin">
                <li>
                    <form id="generalSettingsForm">
                        <input type="hidden" name="csrf_token" value="<?php echo createCsrfToken(); ?>">
                        <div class="uk-margin">
                            <label class="uk-form-label label-username" for="username">Username:</label>
                            <div class="uk-form-controls">
                                <input class="uk-input" id="usernameInput" type="text" value="<?php echo $_SESSION['username'] ?? ''; ?>">
                            </div>
                        </div>
                        <?php if ($isAdmin) : ?>
                            <div class="uk-margin">
                                <label class="uk-form-label label-title" for="title">Title:</label>
                                <div class="uk-form-controls">
                                    <input class="uk-input" id="titleInput" type="text" value="<?php echo $title; ?>">
                                </div>
                            </div>
                        <?php endif; ?>

                        <div class="uk-margin">
                            <label class="uk-form-label" for="iconInput">Icon:</label>
                            <div class="uk-form-controls">
                               <button id="iconDropdownButton" class="uk-button uk-button-default" type="button" title="Select Icon">
    <i id="selectedIcon" class="<?php echo isset($_SESSION['icon']) ? htmlspecialchars($_SESSION['icon']) : 'fas fa-user'; ?>"></i>
</button>

                                <div uk-dropdown="mode: click; pos: bottom-right">
                                    <div class="icon-grid">
                                        <i class="fas fa-user" data-icon="fas fa-user" title="User" onclick="selectIcon(this)"></i>

                                        <?php if ($isAdmin) : ?>
                                            <i class="fas fa-crown" data-icon="fas fa-crown" title="Crown (Admin)" onclick="selectIcon(this)"></i>
                                        <?php endif; ?>

                                        <i class="fas fa-dragon" data-icon="fas fa-dragon" title="Dragon" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-star" data-icon="fas fa-star" title="Star" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-heart" data-icon="fas fa-heart" title="Heart" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-smile" data-icon="fas fa-smile" title="Smile" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-robot" data-icon="fas fa-robot" title="Robot" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-music" data-icon="fas fa-music" title="Music" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-chess-king" data-icon="fas fa-chess-king" title="Chess King" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-gem" data-icon="fas fa-gem" title="Gem" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-frog" data-icon="fas fa-frog" title="Frog" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-bell" data-icon="fas fa-bell" title="Bell" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-coffee" data-icon="fas fa-coffee" title="Coffee" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-leaf" data-icon="fas fa-leaf" title="Leaf" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-fire" data-icon="fas fa-fire" title="Fire" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-ghost" data-icon="fas fa-ghost" title="Ghost" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-bolt" data-icon="fas fa-bolt" title="Lightning" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-hat-wizard" data-icon="fas fa-hat-wizard" title="Wizard Hat" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-anchor" data-icon="fas fa-anchor" title="Anchor" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-skull" data-icon="fas fa-skull" title="Skull" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-spider" data-icon="fas fa-spider" title="Spider" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-snowflake" data-icon="fas fa-snowflake" title="Snowflake" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-rocket" data-icon="fas fa-rocket" title="Rocket" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-bug" data-icon="fas fa-bug" title="Bug" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-hat-cowboy" data-icon="fas fa-hat-cowboy" title="Cowboy Hat" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-cat" data-icon="fas fa-cat" title="Cat" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-skull-crossbones" data-icon="fas fa-skull-crossbones" title="Skull and Crossbones" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-paw" data-icon="fas fa-paw" title="Paw" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-candy-cane" data-icon="fas fa-candy-cane" title="Candy Cane" onclick="selectIcon(this)"></i>
                                        <i class="fas fa-globe" data-icon="fas fa-globe" title="Globe" onclick="selectIcon(this)"></i>
                                    </div>
                                </div>
                                <input type="hidden" id="iconInput" name="icon">
                            </div>
                        </div>



                        <div class="uk-margin">
                            <button type="button" class="uk-button uk-button-primary" onclick="saveSettings()" title="Save">Save</button>
                        </div>
                    </form>
                </li>


                <?php if ($isAdmin) : ?>
                <li>
                    <form id="securitySettingsForm">
                        <input type="hidden" name="csrf_token" value="<?php echo createCsrfToken(); ?>">
                        <div class="uk-margin">
                            <label class="uk-form-label" for="adminKey">Admin Key:</label>
                            <div class="uk-form-controls">
                                <input class="uk-input" id="adminKeyInput" name="adminKey" type="text" value="<?php echo $adminKey; ?>">
                            </div>
                        </div>

                        <div class="uk-margin">
                            <label class="uk-form-label" for="giphyApiKeyInput">Giphy API Key:</label>
                            <div class="uk-form-controls">
                                <input class="uk-input" id="giphyApiKeyInput" name="giphyApiKey" type="text" value="<?php echo htmlspecialchars($data['giphy_api_key']); ?>">
                            </div>
                        </div>

                        <div class="uk-margin">
    <label class="uk-form-label" for="maxUsersInput">Max Users:</label>
    <div class="uk-form-controls">
       <input
            class="uk-input"
            id="maxUsersInput"
            name="maxUsers"
            type="number"
            min="1"
            pattern="\d+"
            title="Please enter numbers only"
            value="<?php echo htmlspecialchars($data['max_users']); ?>"
               oninput="this.value = Math.min(this.value.replace(/[^0-9]/g, ''), 999)"
            required
        >

        </div>
</div>


                        <div class="uk-margin">
                            <button type="button" class="uk-button uk-button-danger" onclick="purgeChat()" title="Purge Chat">Purge Chat</button>
                        </div>
                         <div class="uk-margin">
                            <button type="button" class="uk-button uk-button-primary" onclick="saveSettings()" title="Save">Save</button>
                        </div>


                    </form>
                </li>


                <li>
                   <form id="themeSettingsForm" method="POST">
                       <input type="hidden" name="csrf_token" value="<?php echo createCsrfToken(); ?>">
    <div class="uk-margin">
        <label class="uk-form-label" for="backgroundColorInput">Background Color:</label>
        <input class="uk-input" id="backgroundColorInput" name="backgroundColorInput" type="color" value="<?php echo $data['theme']['background_color']; ?>">
    </div>
    <div class="uk-margin">
        <label class="uk-form-label" for="primaryColorInput">Primary Color:</label>
        <input class="uk-input" id="primaryColorInput" name="primaryColorInput" type="color" value="<?php echo $data['theme']['primary_color']; ?>">
    </div>
    <div class="uk-margin">
        <label class="uk-form-label" for="secondaryColorInput">Secondary Color:</label>
        <input class="uk-input" id="secondaryColorInput" name="secondaryColorInput" type="color" value="<?php echo $data['theme']['secondary_color']; ?>">
    </div>
    <div class="uk-margin">
        <label class="uk-form-label" for="inputBgColorInput">Input Background Color:</label>
        <input class="uk-input" id="inputBgColorInput" name="inputBgColorInput" type="color" value="<?php echo $data['theme']['input_bg_color']; ?>">
    </div>
    <div class="uk-margin">
        <label class="uk-form-label" for="titleBgColorInput">Title Background Color:</label>
        <input class="uk-input" id="titleBgColorInput" name="titleBgColorInput" type="color" value="<?php echo $data['theme']['title_bg_color']; ?>">
    </div>
    <div class="uk-margin">
        <label class="uk-form-label" for="adminBgColorInput">Admin Background Color:</label>
        <input class="uk-input" id="adminBgColorInput" name="adminBgColorInput" type="color" value="<?php echo $data['theme']['admin_bg_color']; ?>">
    </div>
    <div class="uk-margin">
        <label class="uk-form-label" for="adminTextColorInput">Admin Text Color:</label>
        <input class="uk-input" id="adminTextColorInput" name="adminTextColorInput" type="color" value="<?php echo $data['theme']['admin_text_color']; ?>">
    </div>
    <div class="uk-margin">

        <button type="submit" name="saveThemeSettings" class="uk-button uk-button-primary" title="Save">Save</button>
                    <button type="button" name="resetTheme" class="uk-button uk-button-danger" title="Reset to Default" onclick="handleThemeReset()">Reset</button>


    </div>
</form>
                </li>
                <?php endif; ?>
            </ul>
                     <div id="settingsError" class="uk-alert-danger" style="display: none;"></div>
            <div class="uk-text-right">
                <button class="uk-button uk-button-default uk-modal-close" type="button" title="Cancel">Cancel</button>
            </div>


        </div>
    </div>


   <div id="confirmPurgeModal" uk-modal>
    <div class="uk-modal-dialog uk-modal-body">
        <h2 class="uk-modal-title">Confirm Purge</h2>
        <p>Are you sure you want to purge all the chat? This action cannot be undone.</p>
        <p class="uk-text-right">
            <button class="uk-button uk-button-default" type="button" onclick="cancelPurge()">Cancel</button>
            <button class="uk-button uk-button-danger" type="button" onclick="confirmPurge()">Yes, Purge</button>
        </p>
    </div>
</div>


<?php endif; ?>



<script src="https://cdn.jsdelivr.net/npm/uikit@3.21.9/dist/js/uikit.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/uikit@3.21.9/dist/js/uikit-icons.min.js"></script>

<script>

document.addEventListener('DOMContentLoaded', function () {
    const chatKey = getCookie('chat_key');
    if (chatKey) {
        authenticateWithKey(chatKey);
    }

    const keyInput = document.getElementById('keyInput');
    if (keyInput) {
        keyInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                authenticate();
            }
        });
    }

    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        messageInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                sendMessage();
            }
        });
    }

    const settingsButton = document.getElementById('settingsButton');
    if (settingsButton) {
        settingsButton.addEventListener('click', function() {
            const modal = UIkit.modal('#settingsModal');
            modal.show();
        });
    }

    if (localStorage.getItem('authenticated') === 'true') {
        setInterval(fetchNewMessages, 3000);
setInterval(checkKeyStatus, 60000);    }
});


document.addEventListener('DOMContentLoaded', function () {
    const messageInput = document.getElementById('messageInput');
    const mentionDropdown = document.getElementById('mentionDropdown');
    let mentionStartPos = null;

    if (messageInput) {
        messageInput.addEventListener('input', function (e) {
            const cursorPos = messageInput.selectionStart;
            const textBeforeCursor = messageInput.value.substring(0, cursorPos);
            const lastAtSymbol = textBeforeCursor.lastIndexOf('@');

            if (lastAtSymbol !== -1 && (lastAtSymbol === 0 || textBeforeCursor[lastAtSymbol - 1] === ' ')) {
                mentionStartPos = lastAtSymbol;
                const mentionText = textBeforeCursor.substring(lastAtSymbol + 1);

                if (mentionText.length > 0) {
                    fetch(`?search_users=1&prefix=${encodeURIComponent(mentionText)}`)
                        .then(response => response.json())
                        .then(data => {
                            const mentionList = document.getElementById('mentionList');
                            mentionList.innerHTML = '';

                            data.forEach(user => {
                                const li = document.createElement('li');
                                li.textContent = user;
                                li.addEventListener('click', () => {
                                    selectMention(user);
                                });
                                mentionList.appendChild(li);
                            });

                            if (data.length > 0) {
                                mentionDropdown.style.display = 'block';
                            } else {
                                mentionDropdown.style.display = 'none';
                            }
                        })
                        .catch(() => {
                            mentionDropdown.style.display = 'none';
                        });
                } else {
                    mentionDropdown.style.display = 'none';
                }
            } else {
                mentionDropdown.style.display = 'none';
            }
        });
    }

function selectMention(username) {
    const messageInput = document.getElementById('messageInput');
    const cursorPos = messageInput.selectionStart;
    const textBeforeCursor = messageInput.value.substring(0, mentionStartPos);
    const textAfterCursor = messageInput.value.substring(cursorPos);

    // Construct the mention text with a space after it
    const mentionText = `@${username} `;
    const newText = `${textBeforeCursor}${mentionText}${textAfterCursor}`;

    // Set the new value to the input and place the cursor right after the space
    messageInput.value = newText;
    const newCursorPos = textBeforeCursor.length + mentionText.length;
    messageInput.setSelectionRange(newCursorPos, newCursorPos);

    messageInput.focus();
    mentionDropdown.style.display = 'none';
}






});

function sendMessage() {
    const messageInput = document.getElementById('messageInput');
    const message = messageInput.value.trim();

    if (message !== '') {
        // Replace mentions and directly wrap them with a single span tag
        const formattedMessage = message.replace(/@([^\s@]+)/g, '<span class="mention">@$1</span>');

        fetch('', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `send=1&message=${encodeURIComponent(formattedMessage)}`
        })
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                messageInput.value = '';
                displayMessage(data);
            }
        });
    }
}









function selectIcon(iconElement) {
    const iconCode = iconElement.getAttribute('data-icon');
    const settingsIconInput = document.getElementById('iconInput');
    const messageInput = document.getElementById('messageInput');
    const dropdown = UIkit.dropdown(iconElement.closest('.uk-dropdown'));

    if (settingsIconInput && iconElement.closest('#settingsModal')) {
        document.getElementById('selectedIcon').className = iconCode;
        settingsIconInput.value = iconCode;
        UIkit.dropdown(iconElement.closest('.uk-dropdown')).hide();
    } else if (messageInput) {
        const cursorPosition = messageInput.selectionStart;
        const textBefore = messageInput.value.substring(0, cursorPosition);
        const textAfter = messageInput.value.substring(cursorPosition);

        messageInput.value = textBefore + iconCode + ' ' + textAfter;
        const newCursorPosition = cursorPosition + iconCode.length + 1;
        messageInput.setSelectionRange(newCursorPosition, newCursorPosition);
        UIkit.dropdown(iconElement.closest('.uk-dropdown')).hide();
        messageInput.focus();
    }

    dropdown.hide();
}

function updateIconInMessages(newIcon) {
    const currentUid = <?php echo json_encode($_SESSION['uid']); ?>;
    const messageElements = document.querySelectorAll('#messages .message');

    messageElements.forEach(function(messageElement) {
        const userElement = messageElement.querySelector('strong');
        if (userElement && userElement.getAttribute('data-uid') == currentUid) {
            const iconElement = userElement.querySelector('i');
            if (iconElement) {
                iconElement.className = newIcon;
            }
        }
    });

     sessionIcon = newIcon;
    updateSessionIcon(newIcon);
}

function updateSessionIcon(newIcon) {
    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `updateSessionIcon=1&icon=${encodeURIComponent(newIcon)}`
    })
    .then(response => response.json())
    .then(data => {
        if (!data.success) {
            console.error('Failed to update session icon.');
        }
    })
    .catch(error => {
        console.error('Error updating session icon:', error);
    });
}

function sendMessage() {
    const messageInput = document.getElementById('messageInput');
    const message = messageInput.value;

    const formattedMessage = formatMessageForMentions(message);

    if (formattedMessage.trim() !== '') {
        fetch('', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `send=1&message=${encodeURIComponent(formattedMessage)}`
        })
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                messageInput.value = '';
                displayMessage(data);
            }
        });
    }
}

function formatMessageForMentions(message) {
    return message.replace(/@(\w+)/g, '<span class="mention">@$1</span>');
}




function fetchGifs(query) {
    const apiKey = '<?php echo $data['giphy_api_key']; ?>';
    const url = `https://api.giphy.com/v1/gifs/search?api_key=${apiKey}&q=${encodeURIComponent(query)}&limit=10&rating=G`;

    fetch(url)
        .then(response => response.json())
        .then(data => {
            const gifContainer = document.getElementById('gifContainer');
            gifContainer.innerHTML = '';
            data.data.forEach(gif => {
                const img = document.createElement('img');
                img.src = gif.images.fixed_height.url;
                img.alt = gif.title;
                img.onclick = () => sendGif(gif.images.fixed_height.url);
                gifContainer.appendChild(img);
            });
        })
        .catch(error => {
            console.error('Error fetching GIFs:', error);
        });
}

function sendGif(gifUrl) {
    const messageInput = document.getElementById('messageInput');
    messageInput.value += `<img src="${gifUrl}" alt="GIF" class="giphy-gif">`;
    sendMessage();
}

const isAdmin = <?php echo json_encode($isAdmin); ?>;
let sessionIcon = <?php echo json_encode($_SESSION['icon']); ?>;

function displayMessage(data) {
    const messageDiv = document.createElement('div');
    messageDiv.classList.add('message');

    if (data.is_admin) {
        messageDiv.classList.add('admin-message');
    }

    const userSection = document.createElement('div');
    userSection.innerHTML = `<strong data-uid="${data.uid}"><i class="${data.icon}"></i> ${data.user}</strong>`;
    messageDiv.appendChild(userSection);

    const contentSection = document.createElement('div');

    let messageContent = data.message;
    messageContent = messageContent.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

    if (messageContent.includes('giphy-gif')) {
        contentSection.innerHTML = messageContent;
    } else {
        contentSection.innerHTML = replaceEmoticonsWithIcons(messageContent);
    }

    const timestampSection = document.createElement('div');
    timestampSection.classList.add('timestamp');
    timestampSection.innerHTML = `<small>${data.timestamp}</small>`;

    messageDiv.appendChild(contentSection);
    messageDiv.appendChild(timestampSection);

    const messagesContainer = document.getElementById('messages');
    messagesContainer.appendChild(messageDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}







function replaceEmoticonsWithIcons(message) {
    const emoticonMap = {
        ':)': '<i class="fas fa-smile"></i>',
        ';)': '<i class="fas fa-smile-wink"></i>',
        ':D': '<i class="fas fa-laugh"></i>',
        ':(': '<i class="fas fa-frown"></i>',
        ':P': '<i class="fas fa-grin-tongue"></i>',
        ':O': '<i class="fas fa-surprise"></i>',
        'B)': '<i class="fas fa-sunglasses"></i>',
        ':|': '<i class="fas fa-meh"></i>',
        'XD': '<i class="fas fa-grin-squint"></i>',
        ':*': '<i class="fas fa-kiss"></i>',
        ':@': '<i class="fas fa-angry"></i>',
        ':/': '<i class="fas fa-meh-rolling-eyes"></i>',
        ':$': '<i class="fas fa-flushed"></i>',
        'D:': '<i class="fas fa-dizzy"></i>',
        '8-)': '<i class="fas fa-glasses"></i>',
        'X(': '<i class="fas fa-sad-cry"></i>',
        '^_^': '<i class="fas fa-ghost"></i>',
        ':heart:': '<i class="fas fa-heart"></i>'
    };

    return message.replace(/:\)|;\)|:D|:\(|:P|:O|B\)|:\||XD|:\*|:@|:\$|D:|8-\)|X\(|:\//g, match => emoticonMap[match] || match)
                  .replace(/:heart:/g, '<i class="fas fa-heart"></i>')
                  .replace(/\^_\^/g, '<i class="fas fa-ghost"></i>');
}

function fetchNewMessages() {
    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'fetch=1'
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('messages').innerHTML = '';
        if (Array.isArray(data)) {
            data.forEach(displayMessage);
        }
    });
}

function checkKeyStatus() {
    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'checkKey=1'
    })
    .then(response => response.json())
    .then(data => {
        if (data.key_changed && !isAdmin) {
            document.cookie = 'chat_key=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
            localStorage.removeItem('authenticated');
            window.location.reload();
        }
    });
}




function authenticate() {
    const authKeyInput = document.getElementById('keyInput');
    const key = authKeyInput.value;
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;

    if (!key) {
        showAuthError("Key cannot be empty.");
        return;
    }

    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `authenticate=1&key=${encodeURIComponent(key)}&csrf_token=${encodeURIComponent(csrfToken)}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.admin || data.authenticated) {
            localStorage.setItem('authenticated', 'true');
            location.reload();
        } else if (data.error) {
            if (data.error === 'User limit reached') {
                showAuthError("The maximum number of users has been reached. Please try again later.");
            } else {
                showAuthError("Wrong key, try again.");
            }
        }
    })
    .catch(error => {
        console.error('Error during authentication:', error);
        showAuthError("An unexpected error occurred. Please try again.");
    });
}




function showAuthError(message) {
    const authErrorBox = document.getElementById('authError');
    const authErrorMessage = document.getElementById('authErrorMessage');
    authErrorMessage.textContent = message;
    authErrorBox.style.display = 'block';
    setTimeout(() => {
        authErrorBox.style.display = 'none';
    }, 5000);
}




function authenticateWithKey(key) {
    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `authenticate=1&key=${encodeURIComponent(key)}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.admin || data.authenticated) {
            if (localStorage.getItem('authenticated') !== 'true') {
                localStorage.setItem('authenticated', 'true');
                location.reload();
            }
        }
    });
}

function showAlert(message, context = 'general') {
    const authErrorBox = document.getElementById('authError');
    const generalAlertBox = document.getElementById('alertBox');

    if (context === 'auth') {
        if (authErrorBox) {
            authErrorBox.innerText = message;
            authErrorBox.style.display = 'block';
            setTimeout(() => {
                authErrorBox.style.display = 'none';
            }, 3000);
        }
    } else {
        if (generalAlertBox) {
            generalAlertBox.innerText = message;
            generalAlertBox.style.display = 'block';
            setTimeout(() => {
                generalAlertBox.style.display = 'none';
            }, 3000);
        }
    }
}


function logout() {
    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'logout=1'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            document.cookie = 'chat_key=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
            localStorage.removeItem('authenticated');
            window.location.href = window.location.href.split('?')[0];
        } else {
            showAlert('Logout failed');
        }
    });
}

function saveSettings() {
    const usernameInput = document.getElementById('usernameInput');
    const titleInput = document.getElementById('titleInput');
    const adminKeyInput = document.getElementById('adminKeyInput');
    const iconInput = document.getElementById('iconInput');
    const giphyApiKeyInput = document.getElementById('giphyApiKeyInput');
    const maxUsersInput = document.getElementById('maxUsersInput');
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;

    const username = usernameInput ? sanitizeInput(usernameInput.value) : '';
    const title = titleInput ? sanitizeInput(titleInput.value) : '';
    const adminKey = adminKeyInput ? sanitizeInput(adminKeyInput.value) : '';
    const icon = iconInput ? sanitizeInput(iconInput.value) : '';
    const giphyApiKey = giphyApiKeyInput ? sanitizeInput(giphyApiKeyInput.value) : '';
    const maxUsers = maxUsersInput ? sanitizeInput(maxUsersInput.value) : '';

    let requestBody = `saveSettings=1&csrf_token=${encodeURIComponent(csrfToken)}`;
    if (username) requestBody += `&username=${encodeURIComponent(username)}`;
    if (title) requestBody += `&title=${encodeURIComponent(title)}`;
    if (adminKey) requestBody += `&adminKey=${encodeURIComponent(adminKey)}`;
    if (giphyApiKey) requestBody += `&giphyApiKey=${encodeURIComponent(giphyApiKey)}`;
    if (maxUsers) requestBody += `&maxUsers=${encodeURIComponent(maxUsers)}`;

     if (icon) {
        requestBody += `&icon=${encodeURIComponent(icon)}`;
    }

    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: requestBody
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            if (icon) {
                sessionIcon = icon;
                updateIconInMessages(icon);
            }
            UIkit.modal('#settingsModal').hide();
            showAlert('Settings saved successfully');
        } else if (data.error) {
            showSettingsError(data.error);
        } else {
            showSettingsError('Failed to save settings');
        }
    })
    .catch(error => {
        console.error('Error saving settings:', error);
        showSettingsError('An error occurred while saving settings');
    });
}





function showSettingsError(message) {
    const settingsError = document.getElementById('settingsError');
    settingsError.textContent = message;
    settingsError.style.display = 'block';

    setTimeout(() => {
        settingsError.style.display = 'none';
    }, 3000);
}

function saveThemeSettings() {
    const backgroundColor = document.getElementById('backgroundColorInput').value;
    const primaryColor = document.getElementById('primaryColorInput').value;
    const secondaryColor = document.getElementById('secondaryColorInput').value;
    const inputBgColor = document.getElementById('inputBgColorInput').value;
    const titleBgColor = document.getElementById('titleBgColorInput').value;
    const adminBgColor = document.getElementById('adminBgColorInput').value;
    const adminTextColor = document.getElementById('adminTextColorInput').value;
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;

    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `saveThemeSettings=1&csrf_token=${encodeURIComponent(csrfToken)}&backgroundColor=${encodeURIComponent(backgroundColor)}&primaryColor=${encodeURIComponent(primaryColor)}&secondaryColor=${encodeURIComponent(secondaryColor)}&inputBgColor=${encodeURIComponent(inputBgColor)}&titleBgColor=${encodeURIComponent(titleBgColor)}&adminBgColor=${encodeURIComponent(adminBgColor)}&adminTextColor=${encodeURIComponent(adminTextColor)}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            UIkit.modal('#settingsModal').hide();
            showAlert('Theme settings saved successfully');
        } else {
            showAlert('Failed to save theme settings');
        }
    });
}


function handleThemeReset() {
    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'resetTheme=1'
    })
    .then(response => response.json())
    .then(() => {
        UIkit.modal('#settingsModal').hide();
 showAlert('Theme has been reset to default settings.');
        setTimeout(function() {

            location.reload(); // Reload the page to reflect changes
        }, 1500);

    })
    .catch(error => {
        console.error('Error resetting theme:', error);
        showAlert('An error occurred while resetting the theme.');
    });
}

function sanitizeInput(input) {
    const element = document.createElement('div');
    element.innerText = input;
    return element.innerHTML;
}

function generateKey() {
    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'generate=1'
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('keyContainer').innerText = `Key: ${data.key}`;
        document.getElementById('keyContainer').style.display = 'block';
        showAlert('New key generated');
    });
}

function purgeChat() {
     UIkit.modal('#confirmPurgeModal').show();
}


function confirmPurge() {
    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'purge=1'
    })
    .then(response => response.json())
    .then(data => {
        if (data.purged) {
            UIkit.modal('#confirmPurgeModal').hide();
            document.getElementById('messages').innerHTML = '';
            showAlert('Chat has been purged. Re-authenticating...');
            setTimeout(() => {
                document.cookie = 'chat_key=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';

localStorage.removeItem('authenticated');
                window.location.reload();
            }, 1500);
        } else {
            showAlert('Failed to purge chat');
        }
    });
}

function cancelPurge() {
     UIkit.modal('#confirmPurgeModal').hide();

     setTimeout(() => {
        UIkit.modal('#settingsModal').show();
    }, 300);
}

setInterval(function () {
    if (localStorage.getItem('authenticated') === 'true') {
        checkKeyStatus();
    }
}, 5000);

function showAlert(message) {
    const alertBox = document.getElementById('alertBox');
    if (alertBox) {
        alertBox.innerText = message;
        alertBox.style.display = 'block';
        setTimeout(() => {
            alertBox.style.display = 'none';
        }, 3000);
    }
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

function authenticateWithKey(key) {
    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `authenticate=1&key=${encodeURIComponent(key)}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.admin || data.authenticated) {
            if (localStorage.getItem('authenticated') !== 'true') {
                localStorage.setItem('authenticated', 'true');
                location.reload();
            }
        }
    });
}

</script>
<footer class="uk-text-center uk-padding-small uk-background-secondary uk-light">
    2024 © Silk by <a href="https://github.com/blue0x1" target="_blank" class="uk-link-reset">blue0x1</a>
</footer>
</body>
</html>
