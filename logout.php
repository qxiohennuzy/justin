<?php
session_start(); // Start session management
session_destroy(); // Destroy the session
header('Location: index.php'); // Redirect to the login page
exit;
?>