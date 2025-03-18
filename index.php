<?php
session_start(); // Start the session

// Database configuration
$host = 'localhost'; // Database host
$db = 'tmo_shuttle_services'; // Database name
$user = 'root'; // Database username
$pass = ''; // Database password (default for XAMPP/MAMP is often an empty string)

// Establish the connection using PDO
try {
    $conn = new PDO("mysql:host=$host;dbname=$db;charset=utf8", $user, $pass);
    // Set the PDO error mode to exception
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo "Connection failed: " . $e->getMessage();
    exit;
}

// Function to sanitize user input
function sanitizeInput($data) {
    return htmlspecialchars(trim($data));
}

// Initialize error message
$errorMessage = '';

// Handle login
if (isset($_POST['login'])) {
    $username = sanitizeInput($_POST['username']);
    $password = sanitizeInput($_POST['password']);

    $stmt = $conn->prepare("SELECT password, role FROM users WHERE username = ?");
    $stmt->execute([$username]);
    
    if ($stmt->rowCount() > 0) {
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $hashed_password = $row['password'];
        $role = $row['role'];

        if (password_verify($password, $hashed_password)) {
            $_SESSION['username'] = $username; // Store the username

            // Redirect based on role
            if ($role === 'admin') {
                header('Location: homepage.php'); // Redirect to admin dashboard
                exit;
            } elseif ($role === 'staff') {
                header('Location: staff_homepage.php'); // Redirect to staff homepage
                exit;
            }
        } else {
            $errorMessage = 'Invalid password.'; // Update error message
        }
    } else {
        $errorMessage = 'No user found with this username.'; // Update error message for username
    }
}
?>

