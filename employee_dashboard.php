<?php
include 'header.php'; // Include your header
require 'db.php'; // Include your database connection
include 'sidebar.php';

function fetchActiveEmployees($conn) {
    // Modify the SQL query to fetch only active employees
    $stmt = $conn->query("SELECT * FROM employees WHERE isActive = 1");
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

$employees = fetchActiveEmployees($conn);

// Get username from the session for welcome message
$username = isset($_SESSION['username']) ? htmlspecialchars($_SESSION['username']) : 'Admin';

// Path to your TMO logo image
$logoPath = './tmo.jpg';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Employee Dashboard - TMO Shuttle Services</title>
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
            flex-direction: column; /* Make body a column layout */
        }

        /* Main Content Styles */
        .main-content {
            margin-left: 280px; /* Leave space for the sidebar */
            padding: 2rem;
            flex-grow: 1;
            background-color: #e9ecef; /* Background color for main content */
            text-align: center; /* Center-align all text in the main content */
        }

        h1 {
            margin-bottom: 20px;
            color: #007bff;
        }

        .button-container {
            display: flex; /* Use Flexbox for horizontal layout of buttons */
            justify-content: center; /* Center the buttons horizontally */
            gap: 1rem; /* Space between buttons */
            margin-bottom: 20px; /* Space below the button container */
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }

        table, th, td {
            border: 1px solid #ccc;
            padding: 10px;
            text-align: left; /* Ensure text is left-aligned in the table */
        }

        th {
            background: #f2f2f2;
        }

        .back-button {
            padding: 10px 20px; 
            cursor: pointer; 
            background-color: #007BFF; 
            color: white; 
            border: none; 
            border-radius: 5px; 
            transition: background-color 0.3s; 
        }

        .back-button:hover {
            background-color: #0056b3; 
        }

        /* Print Styles */
        @media print {
            body {
                background-color: white; /* Set a white background for print */
            }
            .top-bar, aside, .logout-button, .print-button {
                display: none; /* Hide top bar and sidebar */
            }
            .main-content {
                margin-left: 0; /* Override the left margin */
                padding: 0; /* Remove padding */
            }
            .print-logo {
                display: block; /* Show the logo */
                margin: 0 auto 30px; /* Center the logo and space below it */
                width: auto; /* Use natural width */
                max-width: 150px; /* Set maximum width */
            }
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            aside {
                width: 100%;
                position: relative;
                height: auto; /* Auto height */
                padding-bottom: 1rem; /* Space at the bottom */
                box-shadow: none; /* Remove the shadow */
            }

            .main-content {
                margin-left: 0; /* No left margin */
                padding: 1rem; /* Adjust padding */
            }

            .button-container {
                flex-direction: column; /* Stack buttons on smaller screens */
                gap: 0.5rem; /* Space between buttons when stacked */
            }
        }

        .print-logo {
            display: block; 
            margin: 0 auto 30px; /* Center the logo and space below it */
            width: auto; /* Use natural width */
            max-width: 120px; /* Adjust this value to set the desired maximum size */
        }
    </style>
</head>
<body>
  
    </aside>

    <div class="main-content" id="printArea">
        <img src="<?= $logoPath ?>" alt="TMO Logo" class="print-logo"> <!-- Logo added for print -->
        <h1>Employee Dashboard</h1>
        <div class="button-container">
            <button onclick="printDashboard()" class="back-button print-button">Print Dashboard</button> <!-- Print button added -->
        </div>

        <table>
            <thead>
                <tr>
                    <th>Id</th>
                    <th>First Name</th>
                    <th>Last Name</th>
                    <th>Mobile</th>
                    <th>License Expiration</th>
                    <th>Address</th>
                    <th>Assigned Bus</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($employees)): ?>
                    <tr><td colspan="7">No active employees found.</td></tr>
                <?php else: ?>
                    <?php foreach ($employees as $employee): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($employee['id']); ?></td>
                        <td><?php echo htmlspecialchars($employee['firstName']); ?></td>
                        <td><?php echo htmlspecialchars($employee['lastName']); ?></td>
                        <td><?php echo htmlspecialchars($employee['mobile']); ?></td>
                        <td><?php echo htmlspecialchars($employee['licenseExpiration']); ?></td>
                        <td><?php echo htmlspecialchars($employee['address']); ?></td>
                        <td><?php echo htmlspecialchars($employee['assignedBus']); ?></td>
                    </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <script>
        function toggleDropdown(menuId) {
            const dropdowns = document.querySelectorAll('.dropdown');
            dropdowns.forEach(dropdown => {
                if (dropdown.id === menuId) {
                    dropdown.classList.toggle('open'); // Toggle the visibility of the current dropdown
                } else {
                    dropdown.classList.remove('open'); // Close other dropdowns
                }
            });
        }
        
        function printDashboard() {
            window.print(); // Call print dialog
        }
    </script>
</body>
</html>