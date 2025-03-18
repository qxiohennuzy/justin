<!-- deactivate_form.php -->
<?php
require 'db.php'; // Include your database connection here

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get the data from the POST request
    $id = $_POST['id'];
    $firstName = $_POST['firstName'];
    $lastName = $_POST['lastName'];
    $mobile = $_POST['mobile'];
    $licenseExpiration = $_POST['licenseExpiration'];
    $address = $_POST['address'];
    $assignedBus = $_POST['assignedBus'];

    // You can implement deactivation logic here if needed
    // For example, update the isActive field in the database
    $stmt = $conn->prepare("UPDATE employees SET isActive = 0 WHERE id = ?");
    $stmt->execute([$id]);

    // Optionally display a confirmation message
    $message = "Employee {$firstName} {$lastName} has been successfully deactivated.";
} else {
    // Optional: Redirect back to listing if accessed without POST
    header('Location: index.php'); // Adjust to your listing page
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deactivate Employee Form</title>
</head>
<body>
    <h2>Deactivate Employee</h2>
    <?php if (isset($message)): ?>
        <p><?= htmlspecialchars($message) ?></p>
    <?php endif; ?>
    <form action="" method="post">
        <input type="hidden" name="id" value="<?= htmlspecialchars($id) ?>">
        <div>
            <label>First Name:</label>
            <input type="text" name="firstName" value="<?= htmlspecialchars($firstName) ?>" readonly>
        </div>
        <div>
            <label>Last Name:</label>
            <input type="text" name="lastName" value="<?= htmlspecialchars($lastName) ?>" readonly>
        </div>
        <div>
            <label>Mobile:</label>
            <input type="text" name="mobile" value="<?= htmlspecialchars($mobile) ?>" readonly>
        </div>
        <div>
            <label>License Expiration:</label>
            <input type="date" name="licenseExpiration" value="<?= htmlspecialchars($licenseExpiration) ?>" readonly>
        </div>
        <div>
            <label>Address:</label>
            <input type="text" name="address" value="<?= htmlspecialchars($address) ?>" readonly>
        </div>
        <div>
            <label>Assigned Bus:</label>
            <input type="text" name="assignedBus" value="<?= htmlspecialchars($assignedBus) ?>" readonly>
        </div>
        <div>
            <button type="submit">Confirm Deactivation</button>
        </div>
    </form>
</body>
</html>