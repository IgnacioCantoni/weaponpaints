<?php
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

require_once 'imports/openid.php';
require_once 'imports/db.php'; // Incluye tu conexión PDO a Railway

if (!function_exists("Path")) {
    return;
}

if (!isset($SteamAPI_KEY) || empty($SteamAPI_KEY)) {
    echo 'for website owner:<br>please enter a valid steam web api key.';
    exit;
}

if (isset($_SESSION['steamid'])) {
    header('Location: ' . GetPrefix() . 'skins');
    exit;
}

try {
    // Construir URL base
    $url = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'
        ? "https://" . $_SERVER['SERVER_NAME']
        : "http://" . $_SERVER['SERVER_NAME'] . (($_SERVER['SERVER_PORT'] != 80) ? ':' . $_SERVER['SERVER_PORT'] : '');

    $openid = new LightOpenID($url);

    if (!$openid->mode) {
        $openid->identity = 'https://steamcommunity.com/openid';
        header('Location: ' . $openid->authUrl());
        exit;
    } elseif ($openid->mode == 'cancel') {
        header('Location: ' . GetPrefix());
        exit;
    } else {
        if ($openid->validate()) {
            $urlParts = explode('/', $openid->identity);
            $steamid = end($urlParts);

            if (empty($steamid)) {
                echo 'Error with Steam ID 64. Please contact support.';
                exit;
            }

            $_SESSION['steamid'] = $steamid;

            // Insertar en DB si no existe
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM usuarios WHERE steamid = :steamid");
            $stmt->execute(['steamid' => $steamid]);

            if ($stmt->fetchColumn() == 0) {
                $insert = $pdo->prepare("INSERT INTO usuarios (steamid) VALUES (:steamid)");
                $insert->execute(['steamid' => $steamid]);
            }
        }

        header('Location: ' . GetPrefix());
        exit;
    }
} catch (Exception $exception) {
    $documentError_Code = $exception->getCode();
    $documentError_Message = $exception->getMessage();

    $documentError_Message .= "<br>Please contact the website owner for help.";

    include_once './errorpage.php';
}
