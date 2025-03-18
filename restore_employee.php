<?php
require 'db.php';

if (isset($_POST['id'])) {
    $id = $_POST['id'];

    // Restore the employee
    $updateStmt = $conn->prepare("UPDATE employees SET isActive = 1 WHERE id = ?");
    $updateStmt->execute([$id]);

    // Redirect to bin page
    header('Location: bin.php?message=Employee restored successfully.');
    exit();
} else {
    header('Location: bin.php?error=Invalid request');
    exit();
}