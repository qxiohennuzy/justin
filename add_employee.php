<?php

require 'db.php'; // Include your database connection
include 'header.php';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Collect form data
    $firstName = $_POST['firstName'];
    $lastName = $_POST['lastName'];
    $mobile = $_POST['mobile'];
    $licenseExpiration = $_POST['licenseExpiration'];
    $address = $_POST['address'];
    $assignedBus = $_POST['assignedBus'];

    // Check if an employee with the same details already exists
    $checkStmt = $conn->prepare("SELECT * FROM employees WHERE mobile = ? OR (firstName = ? AND lastName = ? AND address = ?)");
    $checkStmt->execute([$mobile, $firstName, $lastName, $address]);
    $existingEmployee = $checkStmt->fetch();

    if ($existingEmployee) {
        // Show an error message if the employee already exists
        $errorMsg = "The employee details already exists.";
    } else {
        // Prepare the SQL statement for inserting a new employee
        $stmt = $conn->prepare("INSERT INTO employees (firstName, lastName, mobile, licenseExpiration, address, assignedBus) VALUES (?, ?, ?, ?, ?, ?)");
        if ($stmt->execute([$firstName, $lastName, $mobile, $licenseExpiration, $address, $assignedBus])) {
            // Redirect back to the employee list after successful insertion
            header("Location: allemployee.php");
            exit();
        } else {
            $errorMsg = "Error adding new employee.";
        }
    }
}

// Get the username from the session
$username = isset($_SESSION['username']) ? htmlspecialchars($_SESSION['username']) : 'Admin';
$logoPath = '../tmo.jpg'; // Adjust the path to point to your logo
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add New Employee - TMO Shuttle Services</title>
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
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* Main Content Styles */
        .main-content {
            margin-left: 280px; /* Leave space for the sidebar */
            padding: 2rem; /* Padding for main content */
            flex-grow: 1; /* Allow this section to grow */
            background-color: #e9ecef; /* Background color for main content */
        }

        /* Form Container Styles */
        .container {
            max-width: 600px; /* Max width for the form */
            margin: 2rem auto; /* Center the container */
            padding: 2rem; /* Padding around the form */
            background-color: #fff; /* Keep the form background white */
            border-radius: 0.25rem; /* Rounded corners */
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1); /* Shadow effect */
        }

        /* Form Title */
        .container h2 {
            font-size: 1.8rem;
            margin-bottom: 1.5rem;
            color: #007bff; /* Primary color for title */
        }

        /* Form Labels */
        label {
            font-weight: 600; /* Bold labels */
            margin-bottom: 0.5rem; /* Space below labels */
            display: block; /* Labels on their own line */
        }

        /* Form Input Styles */
        input[type="text"],
        input[type="date"],
        select {
            width: 100%; /* Full width of the input */
            padding: 0.75rem; /* Consistent padding */
            border: 1px solid #ced4da; /* Border color */
            border-radius: 0.25rem; /* Rounded corners */
            font-size: 1rem; /* Standard font size */
            transition: border-color 0.2s; /* Transition for border color */
            margin-bottom: 1rem; /* Consistent margin at the bottom */
        }

        input[type="text"]:focus,
        input[type="date"]:focus,
        select:focus {
            border-color: #007bff; /* Border color on focus */
            outline: none; /* Remove outline */
        }

        /* Button Styles */
        button {
            background-color: #007bff; /* Primary button color */
            color: white; /* Button text color */
            padding: 0.75rem 1.5rem; /* Consistent padding */
            border: none; /* Remove border */
            border-radius: 0.25rem; /* Rounded corners */
            font-size: 1rem; /* Standard font size */
            cursor: pointer; /* Show pointer on hover */
            transition: background-color 0.2s, box-shadow 0.2s; /* Transitions */
            margin-right: 1rem; /* Space between buttons */
        }

        button:hover {
            background-color: #0056b3; /* Change color when hovered */
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.15); /* Shadow effect */
        }

        .cancel-button {
            background-color: #dc3545; /* Danger color for cancel button */
        }

        .cancel-button:hover {
            background-color: #c82333; /* Change when hovered */
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            aside {
                width: 100%; /* Full width for sidebar */
                position: relative; /* Change position */
                height: auto; /* Auto height */
                padding-bottom: 1rem; /* Space at the bottom */
                box-shadow: none; /* Remove shadow */
            }

            .main-content {
                margin-left: 0; /* No left margin */
                padding: 1rem; /* Adjust padding */
            }
        }

        .error-message {
            color: red; /* Error message color */
            margin: 1rem 0; /* Space around the message */
        }
    </style>
</head>
<body>
   <?php include 'sidebar.php'; ?>


    <div class="main-content">
        <div class="container">
            <h2>Add New Employee</h2>
            <?php if (isset($errorMsg)): ?>
                <div class="error-message"><?= $errorMsg ?></div>
            <?php endif; ?>
            <form method="POST">
                <label for="firstName">First Name:</label>
                <input type="text" id="firstName" name="firstName" placeholder="First Name" required>

                <label for="lastName">Last Name:</label>
                <input type="text" id="lastName" name="lastName" placeholder="Last Name" required>

                <label for="mobile">Mobile No.:</label>
                <input type="text" id="mobile" name="mobile" placeholder="Mobile No." required>

                <label for="licenseExpiration">License Expiration:</label>
                <input type="date" id="licenseExpiration" name="licenseExpiration" required>

                <label for="address">Address:</label>
                <input type="text" id="address" name="address" placeholder="Address" required>

                <label for="assignedBus">Assign Bus:</label>
                <select id="assignedBus" name="assignedBus" required>
                    <option value="" disabled selected>Select a Bus</option>
                    <option value="BROTHER TALISAY">BROTHER TALISAY</option>
                    <option value="BROTHER ST. TOMAS">BROTHER ST. TOMAS</option>
                    <option value="BROTHER CALAMBA">BROTHER CALAMBA</option>
                    <option value="EPSON GATE 1">EPSON GATE 1</option>
                    <option value="EPSON GATE 2">EPSON GATE 2</option>
                    <option value="EPSON GATE 3">EPSON GATE 3</option>
                    <option value="PHILINAK">PHILINAK</option>
                    <option value="KINPO">KINPO</option>
                    <option value="BTP-ACBEL">BTP-ACBEL</option>
                </select>

                <button type="submit">Add Employee</button>
                <button type="button" class="cancel-button" onclick="window.history.back();">Cancel</button>
            </form>
        </div>
    </div>

    <script>
        // Toggle dropdown menus
        function toggleDropdown(menuId) {
            const dropdowns = document.querySelectorAll('.dropdown');
            dropdowns.forEach(dropdown => {
                if (dropdown.id !== menuId) {
                    dropdown.classList.remove('open'); // Close other dropdowns
                }
            });
            const clickedDropdown = document.getElementById(menuId);
            clickedDropdown.classList.toggle('open'); // Toggle the current dropdown
        }
    </script>
</body>
</html>