<?php
require_once 'imports/db.php';
$host = 'shuttle.proxy.rlwy.net';
$port = 23851;
$user = 'root';
$password = 'vPRKYwpxLAHlzmXXZzZMfyzLDTqFbnUM';
$database = 'railway';

// Crear conexión
$conn = new mysqli($host, $user, $password, $database, $port);

// Verificar conexión
if ($conn->connect_error) {
    die("Conexión fallida: " . $conn->connect_error);
}

// Opcional: establecer el charset
$conn->set_charset("utf8");

// Podés usar la variable $conn en el resto de tu proyecto
