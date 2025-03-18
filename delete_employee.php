<?php
require 'db.php';

if (isset($_POST['id'])) {
    $id = $_POST['id'];

    // Delete the employee from the database
    $deleteStmt = $conn->prepare("DELETE FROM employees WHERE id = ?");
    $deleteStmt->execute([$id]);

    // Redirect to bin page
    header('Location: bin.php?message=Employee deleted successfully.');
    exit();
} else {
    header('Location: bin.php?error=Invalid request');
    exit();
}