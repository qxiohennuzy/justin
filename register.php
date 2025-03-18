<?php
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

// Initialize registration message
$registrationMessage = '';
$errorMessage = '';

// Handle registration
if (isset($_POST['register'])) {
    $username = sanitizeInput($_POST['username']);
    $password = password_hash(sanitizeInput($_POST['password']), PASSWORD_DEFAULT);
    
    // Validate role input
    $role = sanitizeInput($_POST['role']);
    if (!in_array($role, ['admin', 'staff'])) {
        $errorMessage = 'Invalid role selected.';
    } else {
        // Prepared statements to prevent SQL injection
        $stmt = $conn->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
        if ($stmt->execute([$username, $password, $role])) {
            $registrationMessage = 'Registration successful!';
        } else {
            $errorMessage = 'Error: Could not register the user.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Registration</title>
    <style>
        body {
            display: flex;
            justify-content: center; /* Center horizontally */
            align-items: center; /* Center vertically */
            min-height: 100vh; /* Full viewport height */
            font-family: Arial, sans-serif;
            margin: 0; /* Ensure no default margin */
            background: linear-gradient(135deg, #3a7bd5 0%, #00d2ff 100%); /* Colorful gradient */
        }
        .registration-container {
            max-width: 400px; /* Limit width of the form */
            width: 100%; /* Make it responsive */
            padding: 25px; /* Increased padding for better touch targets */
            border: none;
            border-radius: 10px; /* Slightly larger border radius for a softer look */
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2); /* Deeper shadow */
            background-color: white; /* Background color of the form */
            display: flex;
            flex-direction: column; /* Stack items vertically */
            align-items: center; /* Center items horizontally */
        }
        h2 {
            text-align: center;
            margin-bottom: 20px; /* Space below the title */
            color: #333; /* Darker text for the title */
            font-weight: 600; /* Slightly bolder font weight */
        }
        input, select, button {
            width: 100%; /* Full width of the form */
            padding: 12px; /* Increased padding for better touch targets */
            margin: 10px 0; /* Space between items */
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 16px; /* Standard font size */
            box-sizing: border-box; /* Include padding in width */
            transition: border-color 0.3s; /* Transition for border color on focus */
        }
        input:focus, select:focus {
            border-color: #007BFF; /* Change border color on focus */
            outline: none; /* Remove default outline */
            box-shadow: 0 0 5px rgba(0, 123, 255, 0.5); /* Add a subtle shadow */
        }
        button {
            background-color: #007BFF;
            color: white; /* Button text color */
            border: none;
            cursor: pointer;
            font-weight: bold; /* Bolder button text */
        }
        button:hover {
            background-color: #0056b3; /* Change color when hovered */
        }
        .register-link {
            text-align: center;
            margin-top: 10px;
        }
        .register-link a {
            color: #007BFF; /* Link color */
            text-decoration: none; /* No underline */
        }
        .register-link a:hover {
            text-decoration: underline; /* Underline on hover */
        }
        .message {
            width: 100%;
            text-align: center;
            margin-bottom: 15px; /* Space below message */
        }
        .success {
            color: green; /* Green color for success messages */
        }
        .error {
            color: red; /* Red color for error messages */
        }
    </style>
</head>
<body>
    <div class="registration-container">
        <h2>User Registration</h2>
        <form method="post" action="">
            <div class="message">
                <?php if ($registrationMessage): ?>
                    <div class="success"><?= $registrationMessage; ?></div>
                <?php elseif ($errorMessage): ?>
                    <div class="error"><?= $errorMessage; ?></div>
                <?php endif; ?>
            </div>
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <select name="role" required>
                <option value="admin">Admin</option>
                <option value="staff">Staff</option>
            </select>
            <button type="submit" name="register">Register</button>
        </form>

        <div class="register-link">
            <p>Already have an account? <a href="login.php">Login</a></p>
        </div>
    </div>
</body>
</html>