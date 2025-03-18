<?php
require 'db.php';

if (isset($_GET['id'])) {
    $id = $_GET['id'];

    // Fetch the employee details
    $stmt = $conn->prepare("SELECT * FROM employees WHERE id = ?");
    $stmt->execute([$id]);
    $employee = $stmt->fetch();

    if (!$employee) {
        header('Location: index.php?error=Employee not found');
        exit();
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Deactivate the employee
        $updateStmt = $conn->prepare("UPDATE employees SET isActive = 0 WHERE id = ?");
        $updateStmt->execute([$id]);

        // Redirect back to the employee list
        header('Location: index.php?message=Employee deactivated successfully.');
        exit();
    }
} else {
    header('Location: index.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Deactivate Employee</title>
</head>
<body>
    <h2>Deactivate Employee</h2>
    <form method="POST">
        <p>Are you sure you want to deactivate <?= htmlspecialchars($employee['firstName'] . " " . $employee['lastName']) ?>?</p>
        <button type="submit">Confirm Deactivation</button>
    </form>
    <a href="index.php">Cancel</a>
</body>
</html>