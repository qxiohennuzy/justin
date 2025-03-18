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

    // Update the isActive field in the database to deactivate the employee
    $stmt = $conn->prepare("UPDATE employees SET isActive = 0 WHERE id = ?");
    $stmt->execute([$id]);

    // Optionally display a confirmation message
    $message = "Employee {$firstName} {$lastName} has been successfully deactivated.";
} else {
    // Optional: Redirect back to listing if accessed without POST
    header('Location: index.php'); // Adjust to your listing page
    exit();
}

// Store the values to be displayed in the form
$employeeData = [
    'id' => htmlspecialchars($id),
    'firstName' => htmlspecialchars($firstName),
    'lastName' => htmlspecialchars($lastName),
    'mobile' => htmlspecialchars($mobile),
    'licenseExpiration' => htmlspecialchars($licenseExpiration),
    'address' => htmlspecialchars($address),
    'assignedBus' => htmlspecialchars($assignedBus),
];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deactivate Employee</title>
    <link href="https://fonts.googleapis.com/css2?family=Segoe+UI:wght@400;600&display=swap" rel="stylesheet">
    <link href='https://unpkg.com/boxicons@2.1.4/css/boxicons.min.css' rel='stylesheet'>
    <style>
        /* General Reset and Body Styles */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa; /* Light gray background */
            color: #333;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        h2 {
            color: #007bff;
            text-align: center;
            margin-bottom: 20px;
        }
        form {
            max-width: 600px;
            margin: 0 auto;
            background: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        div {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
        }
        input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        button {
            display: block;
            width: 100%;
            padding: 10px;
            background-color: #007BFF;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s;
        }
        button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <h2>Deactivate Employee</h2>
    <?php if (isset($message)): ?>
        <p><?= htmlspecialchars($message) ?></p>
    <?php endif; ?>
    <form action="" method="post">
        <input type="hidden" name="id" value="<?= $employeeData['id'] ?>">
        <div>
            <label>First Name:</label>
            <input type="text" name="firstName" value="<?= $employeeData['firstName'] ?>" readonly>
        </div>
        <div>
            <label>Last Name:</label>
            <input type="text" name="lastName" value="<?= $employeeData['lastName'] ?>" readonly>
        </div>
        <div>
            <label>Mobile:</label>
            <input type="text" name="mobile" value="<?= $employeeData['mobile'] ?>" readonly>
        </div>
        <div>
            <label>License Expiration:</label>
            <input type="date" name="licenseExpiration" value="<?= $employeeData['licenseExpiration'] ?>" readonly>
        </div>
        <div>
            <label>Address:</label>
            <input type="text" name="address" value="<?= $employeeData['address'] ?>" readonly>
        </div>
        <div>
            <label>Assigned Bus:</label>
            <input type="text" name="assignedBus" value="<?= $employeeData['assignedBus'] ?>" readonly>
        </div>
        <div>
            <button type="submit">Confirm Deactivation</button>
        </div>
    </form>
</body>
</html>