<?php
include 'header.php';
require 'db.php'; // Include your database connection
include 'sidebar.php';

// Fetch all active employees
$stmt = $conn->query("SELECT * FROM employees WHERE isActive = 1");
$employees = $stmt->fetchAll();

// Get the username from the session
$username = isset($_SESSION['username']) ? htmlspecialchars($_SESSION['username']) : 'Admin';

// Path to your TMO logo image
$logoPath = '../tmo.jpg';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Active Employees - TMO Shuttle Services</title>
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
            background-color: #f4f4f9; /* Soft light background */
            color: #333;
            display: flex;
            min-height: 100vh;
            overflow-x: hidden; 
            flex-direction: column; 
        }

     


        /* Main Content Styles */
        .main-content {
            margin-left: 280px; 
            padding: 2rem;
            flex-grow: 1; 
            background-color: #e9ecef;
        }

        h2 {
            text-align: left; 
            margin-bottom: 20px;
            color: #343a40; 
        }

        /* Table styles */
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }

        table, th, td {
            border: 1px solid #ccc;
            padding: 12px;
            text-align: left; 
        }

        th {
            background: #f2f2f2; 
            font-weight: bold;
        }

        .search-container {
            margin-bottom: 20px;
            display: flex;
            justify-content: flex-start;
            align-items: center;
            width: 100%;
            max-width: 600px; 
        }

        input[type="text"] {
            padding: 10px;
            width: 100%;
            max-width: 300px; 
            border: 1px solid #ccc;
            border-radius: 4px;
            margin-right: 8px;
        }

        .action-button {
            padding: 10px 15px; 
            cursor: pointer; 
            font-size: 14px; 
            margin-left: 5px; 
            border: none; 
            border-radius: 5px; 
            transition: background-color 0.3s, transform 0.2s; 
            text-decoration: none; 
            color: white; 
        }

        .action-button:hover {
            transform: translateY(-1px); 
        }

        .action-button.add {
            background-color: #007BFF;
        }

        .action-button.view-deactivate {
            background-color: #007BFF;
        }

        .action-button.edit {
            background-color: #007BFF;
        }

        .action-button.deactivate {
            background-color: #dc3545; 
        }

        .action-button.deactivate:hover {
            background-color: #c82333; 
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            aside {
                position: absolute; /* Change positioning to absolute */
                width: 250px; /* Reduced sidebar width */
                height: calc(100% - 60px); 
                left: 0;
                top: 60px; 
                transform: translateX(-100%); 
            }

            aside.active {
                transform: translateX(0); 
            }

            aside.hidden {
                transform: translateX(-100%); 
            }

            .toggle-button {
                display: block; /* Show toggle button */
            }

            .main-content {
                margin-left: 0; /* Remove sidebar margin */
                padding: 1rem;
            }

            th, td {
                font-size: 14px; 
            }
        }
    </style>
</head>
<body>
  

  

    <div class="main-content">
        <h2>Active Employees</h2>
        <div class="search-container">
            <input type="text" id="searchBar" placeholder="Search employees...">
            <a href="add_employee.php" class="action-button add">Add Employee</a> 
            <a href="bin.php" class="action-button view-deactivate">View Resigned Employees</a> 
        </div>
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
                <?php if (empty($employees)): ?>
                    <tr><td colspan="8">No active employees found.</td></tr>
                <?php else: ?>
                    <?php foreach ($employees as $employee): ?>
                    <tr>
                        <td><?= htmlspecialchars($employee['id']) ?></td>
                        <td><?= htmlspecialchars($employee['firstName']) ?></td>
                        <td><?= htmlspecialchars($employee['lastName']) ?></td>
                        <td><?= htmlspecialchars($employee['mobile']) ?></td>
                        <td><?= htmlspecialchars($employee['licenseExpiration']) ?></td>
                        <td><?= htmlspecialchars($employee['address']) ?></td>
                        <td><?= htmlspecialchars($employee['assignedBus']) ?></td>
                        <td>
                            <a href="edit_employee.php?id=<?= $employee['id'] ?>" class="action-button edit">Edit</a>
                            <a href="new_deactivate.php?id=<?= $employee['id'] ?>" class="action-button deactivate">Deactivate</a>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <script>
        // Function to toggle dropdown menus
        function toggleDropdown(menuId) {
            const dropdown = document.getElementById(menuId);
            dropdown.classList.toggle('open');
            dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block'; 
        }

        // Filter employees by search input
        document.getElementById('searchBar').addEventListener('keyup', function() {
            const query = this.value.toLowerCase();
            const rows = document.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                const isMatch = Array.from(cells).some(cell => 
                    cell.textContent.toLowerCase().includes(query)
                );
                row.style.display = isMatch ? '' : 'none';
            });
        });

        function toggleSidebar() {
            const sidebar = document.querySelector('aside');
            sidebar.classList.toggle('active'); // Show or hide sidebar
        }
    </script>
</body>
</html>