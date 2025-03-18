<?php
include 'header.php';
require 'db.php'; // Include your database connection

// Get employee ID from the URL
if (isset($_GET['id']) && is_numeric($_GET['id'])) {
    $employeeId = (int)$_GET['id'];

    // Fetch employee data
    $stmt = $conn->prepare("SELECT * FROM employees WHERE id = :id AND isActive = 1");
    $stmt->execute(['id' => $employeeId]);
    $employee = $stmt->fetch();

    if (!$employee) {
        // If the employee does not exist, redirect
        header("Location: allemployee.php");
        exit();
    }
} else {
    header("Location: allemployee.php");
    exit();
}

// Get the username from the session
$username = isset($_SESSION['username']) ? htmlspecialchars($_SESSION['username']) : 'Admin';

// Path to your TMO logo image
$logoPath = '../tmo.jpg';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get form data
    $firstName = htmlspecialchars($_POST['firstName']);
    $lastName = htmlspecialchars($_POST['lastName']);
    $mobile = htmlspecialchars($_POST['mobile']);
    $licenseExpiration = htmlspecialchars($_POST['licenseExpiration']);
    $address = htmlspecialchars($_POST['address']);
    $assignedBus = htmlspecialchars($_POST['assignedBus']);

    // Prepare update statement
    $updateStmt = $conn->prepare("UPDATE employees SET firstName = :firstName, lastName = :lastName, 
                                  mobile = :mobile, licenseExpiration = :licenseExpiration, 
                                  address = :address, assignedBus = :assignedBus 
                                  WHERE id = :id");

    // Execute the statement
    $updateStmt->execute([
        'firstName' => $firstName,
        'lastName' => $lastName,
        'mobile' => $mobile,
        'licenseExpiration' => $licenseExpiration,
        'address' => $address,
        'assignedBus' => $assignedBus,
        'id' => $employeeId
    ]);

    // Redirect back to the employee list
    header("Location: allemployee.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Employee - TMO Shuttle Services</title>
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
            flex-direction: column; /* Make body a column layout */
        }

        /* Sidebar Styles */
        aside {
            background-color: #343a40; /* Dark Gray Sidebar */
            color: #fff;
            width: 280px;
            height: calc(100vh - 60px); /* Full height minus header height */
            position: fixed;
            left: 0;
            top: 60px; /* Move down by the height of the header */
            padding-top: 56px;
            overflow-y: auto;
            box-shadow: 2px 0 10px rgba(0, 0, 0, 0.15);
        }

        aside ul {
            list-style: none;
            padding: 0;
        }

        aside li {
            margin-bottom: 0.5rem;
        }

        aside a {
            display: block;
            padding: 1rem 1.5rem;
            color: #c6c8ca;
            text-decoration: none; 
            transition: background-color 0.3s, color 0.3s, border-left 0.3s;
            border-left: 3px solid transparent; 
            border-radius: 0.25rem; 
        }

        aside a:hover,
        aside a.active {
            background-color: rgba(255, 255, 255, 0.1);
            color: #ffffff;
            border-left: 3px solid #007bff; 
        }

        /* Dropdown Styles */
        .dropdown {
            display: none; 
            padding-left: 10px; 
        }

        /* Main Content Styles */
        .main-content {
            margin-left: 280px; 
            padding: 2rem; 
            flex-grow: 1; 
            display: flex; 
            flex-direction: column; 
            margin-top: 60px; 
            overflow-y: auto; 
        }

        /* Form Container Styles */
        .container {
            max-width: 600px; 
            margin: 2rem auto; 
            padding: 2rem; 
            background-color: #fff; 
            border-radius: 0.25rem; 
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1); 
        }

        /* Form Title */
        .container h2 {
            font-size: 1.8rem;
            margin-bottom: 1.5rem;
            color: #007bff;
        }

        /* Form Labels */
        label {
            font-weight: 600; 
            margin-bottom: 0.5rem; 
            display: block; 
        }

        /* Form Input Styles */
        input[type="text"],
        input[type="tel"],
        input[type="date"],
        select {
            width: 100%; 
            padding: 0.75rem; 
            border: 1px solid #ced4da; 
            border-radius: 0.25rem; 
            font-size: 1rem; 
            transition: border-color 0.2s; 
            margin-bottom: 1rem; 
        }

        input[type="text"]:focus,
        input[type="tel"]:focus,
        input[type="date"]:focus,
        select:focus {
            border-color: #007bff; 
            outline: none; 
        }

        /* Button Styles */
        button {
            background-color: #007bff; 
            color: white; 
            padding: 0.75rem 1.5rem; 
            border: none; 
            border-radius: 0.25rem; 
            font-size: 1rem; 
            cursor: pointer; 
            transition: background-color 0.2s, box-shadow 0.2s; 
            margin-right: 1rem; 
        }

        button:hover {
            background-color: #0056b3; 
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.15); 
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            aside {
                width: 100%; 
                position: relative; 
                height: auto; 
                padding-bottom: 1rem; 
                box-shadow: none; 
            }

            .main-content {
                margin-left: 0; 
                padding: 1rem; 
            }

            .container {
                margin: 1rem; 
                padding: 1.5rem; 
            }
        }
    </style>
</head>
<body>

    <!-- Sidebar -->
    <aside class="sidebar">
        <nav class="sidebar-nav">
            <ul>
                <li>
                    <a href="index.php"><i class='bx bxs-dashboard'></i><span class="link-name">Dashboard</span></a>
                </li>
                <li>
                    <a href="javascript:void(0)" onclick="toggleDropdown('busManagement')"><i class='bx bxs-bus'></i> Bus Management</a>
                    <ul id="busManagement" class="dropdown">
                        <li><a href="add_bus.php">Add Bus</a></li>
                        <li><a href="all_buses.php">All Buses</a></li>
                    </ul>
                </li>
                <li>
                    <a href="javascript:void(0)" onclick="toggleDropdown('employeeManagement')"><i class='bx bxs-user'></i> Employee Management</a>
                    <ul id="employeeManagement" class="dropdown">
                        <li><a href="add_employee.php">Add Employee</a></li>
                        <li><a href="allemployee.php">All Employees</a></li>
                        <li><a href="manage_employee.php">Manage Employees</a></li>
                    </ul>
                </li>
                <li>
                    <a href="javascript:void(0)" onclick="toggleDropdown('schedulingManagement')"><i class='bx bxs-calendar'></i> Scheduling</a>
                    <ul id="schedulingManagement" class="dropdown">
                        <li><a href="add_booking.php">Add Booking</a></li>
                        <li><a href="all_booking.php">All Bookings</a></li>
                        <li><a href="bus_ticket.php">Print Trip Ticket</a></li>
                    </ul>
                </li>
                <li>
                    <a href="javascript:void(0)" onclick="toggleDropdown('reportsManagement')"><i class='bx bxs-report'></i> All Reports</a>
                    <ul id="reportsManagement" class="dropdown">
                        <li><a href="employee_dashboard.php">Employee Report</a></li>
                        <li><a href="booking_dashboard.php">Scheduling Report</a></li>
                        <li><a href="bus_dashboard.php">Bus Management Report</a></li>
                    </ul>
                </li>
            </ul>
        </nav>
    </aside>

    <div class="main-content">
        <div class="container">
            <h2>Edit Employee</h2>
            <form method="POST" action="edit_employee.php?id=<?= htmlspecialchars($employeeId) ?>">
                <label for="firstName">First Name:</label>
                <input type="text" id="firstName" name="firstName" value="<?= htmlspecialchars($employee['firstName']) ?>" required>

                <label for="lastName">Last Name:</label>
                <input type="text" id="lastName" name="lastName" value="<?= htmlspecialchars($employee['lastName']) ?>" required>

                <label for="mobile">Mobile No:</label>
                <input type="tel" id="mobile" name="mobile" value="<?= htmlspecialchars($employee['mobile']) ?>" required>

                <label for="licenseExpiration">License Expiration:</label>
                <input type="date" id="licenseExpiration" name="licenseExpiration" value="<?= htmlspecialchars($employee['licenseExpiration']) ?>" required>

                <label for="address">Address:</label>
                <input type="text" id="address" name="address" value="<?= htmlspecialchars($employee['address']) ?>" required>

                <label for="assignedBus">Assigned Bus:</label>
                <select id="assignedBus" name="assignedBus" required>
                    <option value="" disabled>Select a Bus</option>
                    <option value="BROTHER TALISAY" <?= ($employee['assignedBus'] === 'BROTHER TALISAY') ? 'selected' : '' ?>>BROTHER TALISAY</option>
                    <option value="BROTHER ST. TOMAS" <?= ($employee['assignedBus'] === 'BROTHER ST. TOMAS') ? 'selected' : '' ?>>BROTHER ST. TOMAS</option>
                    <option value="BROTHER CALAMBA" <?= ($employee['assignedBus'] === 'BROTHER CALAMBA') ? 'selected' : '' ?>>BROTHER CALAMBA</option>
                    <option value="EPSON GATE 1" <?= ($employee['assignedBus'] === 'EPSON GATE 1') ? 'selected' : '' ?>>EPSON GATE 1</option>
                    <option value="EPSON GATE 2" <?= ($employee['assignedBus'] === 'EPSON GATE 2') ? 'selected' : '' ?>>EPSON GATE 2</option>
                    <option value="EPSON GATE 3" <?= ($employee['assignedBus'] === 'EPSON GATE 3') ? 'selected' : '' ?>>EPSON GATE 3</option>
                    <option value="PHILINAK" <?= ($employee['assignedBus'] === 'PHILINAK') ? 'selected' : '' ?>>PHILINAK</option>
                    <option value="KINPO" <?= ($employee['assignedBus'] === 'KINPO') ? 'selected' : '' ?>>KINPO</option>
                    <option value="BTP-ACBEL" <?= ($employee['assignedBus'] === 'BTP-ACBEL') ? 'selected' : '' ?>>BTP-ACBEL</option>
                </select>

                <button type="submit">Update Employee</button>
                <button type="button" class="back-button" onclick="window.history.back();">Cancel</button>
            </form>
        </div>
    </div>

    <script>
        function toggleDropdown(menuId) {
            const dropdowns = document.querySelectorAll('.dropdown');
            dropdowns.forEach(dropdown => {
                dropdown.style.display = 'none'; // Hide other dropdowns
            });
            const clickedDropdown = document.getElementById(menuId);
            clickedDropdown.style.display = clickedDropdown.style.display === 'block' ? 'none' : 'block'; // Toggle current dropdown display
        }

        // Hide all dropdowns by default
        document.querySelectorAll('.dropdown').forEach(dropdown => {
            dropdown.style.display = 'none';
        });
    </script>
</body>
</html>