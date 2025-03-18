<?php
// Database configuration
$host = 'localhost'; // Database host
$db = 'tmo_shuttle_services'; // Database name
$user = 'root'; // Database username
$pass = ''; // Database password (default for XAMPP/MAMP is often an empty string)

try {
    // Establish the connection
    $conn = new PDO("mysql:host=$host;dbname=$db;charset=utf8", $user, $pass);
    // Set the PDO error mode to exception
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    // If the connection fails, display an error message
    echo "Connection failed: " . $e->getMessage();
    exit; // Terminate the script
}
?>