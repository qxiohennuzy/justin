<?php
include 'header.php';
require 'db.php'; // Include your database connection
include 'sidebar.php';

// Fetch all deactivated employees
$stmt = $conn->query("SELECT * FROM employees WHERE isActive = 0");
$deactivatedEmployees = $stmt->fetchAll();

// Get username from the session for welcome message
$username = isset($_SESSION['username']) ? htmlspecialchars($_SESSION['username']) : 'Admin';

// Path to your TMO logo image
$logoPath = '../tmo.jpg';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deactivated Employees - TMO Shuttle Services</title>
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
            overflow-x: hidden; /* Prevent horizontal overflow */
            flex-direction: column; /* Make body a column layout */
        }


      

        /* Main Content Styles */
        .main-content {
            margin-left: 280px; /* Leave space for the sidebar */
            padding: 2rem;
            flex-grow: 1; 
            background-color: #e9ecef; /* Background color for main content */
        }

        h2 {
            margin-bottom: 20px;
            text-align: center;
            color: #007bff; /* Change title color */
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }

        table, th, td {
            border: 1px solid #ccc;
            padding: 10px;
            text-align: left;
        }

        th {
            background: #f2f2f2;
        }

        .action-button {
            padding: 10px 15px; 
            cursor: pointer; 
            font-size: 14px; 
            margin-left: 5px; 
            background-color: #007BFF; 
            color: white; 
            border: none; 
            border-radius: 4px; 
            transition: background-color 0.3s; 
        }

        .action-button:hover {
            background-color: #0056b3; 
        }

        .dropdown {
            display: none; /* Hide dropdowns by default */
            padding-left: 20px; /* Indent dropdown items */
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            aside {
                width: 100%; /* Full width for sidebar */
                position: relative; /* Position relative on small screens */
                height: auto; /* Auto height */
                padding-bottom: 1rem; /* Space at the bottom */
                box-shadow: none; /* Remove the shadow */
            }

            .main-content {
                margin-left: 0; /* No left margin */
                padding: 1rem; /* Adjust padding */
            }
        }
    </style>
</head>
<body>
  


    <div class="main-content">
        <div class="container">
            <h2>Deactivated Employees</h2>
            <table>
                <thead>
                    <tr>
                        <th>Id No</th>
                        <th>First Name</th>
                        <th>Last Name</th>
                        <th>Mobile No</th>
                        <th>License Expiration</th>
                        <th>Address</th>
                        <th>Assigned Bus</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($deactivatedEmployees)): ?>
                        <tr><td colspan="8">No deactivated employees found.</td></tr>
                    <?php else: ?>
                        <?php foreach ($deactivatedEmployees as $employee): ?>
                        <tr>
                            <td><?= htmlspecialchars($employee['id']) ?></td>
                            <td><?= htmlspecialchars($employee['firstName']) ?></td>
                            <td><?= htmlspecialchars($employee['lastName']) ?></td>
                            <td><?= htmlspecialchars($employee['mobile']) ?></td>
                            <td><?= htmlspecialchars($employee['licenseExpiration']) ?></td>
                            <td><?= htmlspecialchars($employee['address']) ?></td>
                            <td><?= htmlspecialchars($employee['assignedBus']) ?></td>
                            <td>
                                <form action="restore_employee.php" method="POST" style="display:inline;">
                                    <input type="hidden" name="id" value="<?= $employee['id'] ?>">
                                    <button type="submit" class="action-button">Restore</button>
                                </form>
                                <form action="delete_employee.php" method="POST" style="display:inline;">
                                    <input type="hidden" name="id" value="<?= $employee['id'] ?>">
                                    <button type="submit" class="action-button" onclick="return confirm('Are you sure you want to permanently delete this employee?');">Delete</button>
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
            <a href="allemployee.php" class="action-button">Back to Employee List</a>
        </div>
    </div>

    <script>
        function toggleDropdown(menuId) {
            const dropdowns = document.querySelectorAll('.dropdown');
            dropdowns.forEach(dropdown => {
                if (dropdown.id !== menuId) {
                    dropdown.style.display = 'none'; // Hide other dropdowns
                }
            });
            const clickedDropdown = document.getElementById(menuId);
            clickedDropdown.style.display = clickedDropdown.style.display === 'block' ? 'none' : 'block'; // Toggle the current dropdown
        }
        
        // Initial state set to hide dropdowns
        document.querySelectorAll('.dropdown').forEach(dropdown => {
            dropdown.style.display = 'none';
        });
    </script>
</body>
</html>