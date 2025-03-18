<?php
session_start(); // Start the session to access session variables
require 'db.php'; // Include your database connection

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
        header('Location: allemployee.php?message=Employee deactivated successfully.');
        exit();
    }
} else {
    header('Location: allemployee.php');
    exit();
}

// Get the username from the session for the welcome message
$username = isset($_SESSION['username']) ? htmlspecialchars($_SESSION['username']) : 'Admin';
$logoPath = '../tmo.jpg'; // Adjust the path to point to your logo
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
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* Top Bar Styles */
        .top-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1rem 1.5rem;
            background-color: #fff;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
            position: fixed;
            width: 100%;
            z-index: 10;
        }

        .logo {
            height: 50px;
            width: auto;
        }

        .site-title {
            font-size: 1.5rem;
            color: #333;
        }

        .user-info {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .user-info strong {
            font-weight: 600;
        }

        .logout-button {
            background-color: white;
            color: red;
            border: 1px solid red;
            border-radius: 5px;
            padding: 0.5rem 1rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 1rem;
            transition: background-color 0.3s, color 0.3s;
        }

        .logout-button:hover {
            background-color: red;
            color: white;
        }

        /* Sidebar Styles */
        aside {
            background-color: #343a40;
            color: #fff;
            width: 280px;
            height: calc(100vh - 60px); /* Adjust for top bar height */
            position: fixed;
            left: 0;
            top: 60px; /* Adjust to sit below the top bar */
            padding-top: 20px;
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
            border-left: 3px solid transparent; /* Left border */
            transition: background-color 0.3s, color 0.3s, border-left 0.3s;
            border-radius: 0.25rem;
        }

        aside a:hover,
        aside a.active {
            background-color: rgba(255, 255, 255, 0.1);
            color: #fff;
            border-left: 3px solid #007bff;
        }

        /* Dropdown Styles */
        .dropdown {
            display: none; /* Hide dropdown by default */
            padding-left: 20px; /* Indent dropdown */
        }

        .dropdown.open {
            display: block; /* Show dropdown when open */
        }

        /* Main Content Styles */
        .main-content {
            margin-left: 280px; /* Leave space for the sidebar */
            padding: 2rem;
            flex-grow: 1; 
            margin-top: 60px; /* Adjust margin for top bar */
            background-color: #e9ecef; /* Background color for main content */
            display: flex; /* Use flexbox for centering */
            align-items: center; /* Center vertically */
            justify-content: center; /* Center horizontally */
        }

        /* Form Container Styles */
        .container {
            max-width: 600px; /* Max width for the form */
            width: 100%; /* Full width for smaller screens */
            background-color: white; /* White background for the form */
            padding: 2rem; /* Padding for the form content */
            border-radius: 5px; /* Rounded corners */
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1); /* Shadow for depth */
            text-align: center; /* Centered text */
        }

        /* Form Title */
        .container h2 {
            font-size: 1.8rem; /* Heading size */
            margin-bottom: 1.5rem; /* Space under heading */
            color: #007bff; /* Color for primary headings */
        }

        /* Button Styles */
        button {
            padding: 10px 20px; 
            font-size: 16px; 
            background-color: #007bff; /* Primary button color */
            color: white; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
            transition: background-color 0.3s; /* Smooth transition */
        }

        button:hover {
            background-color: #0056b3; /* Darker shade on hover */
        }

        a {
            display: inline-block; /* Make the cancel link a block */
            margin-top: 1rem; 
            color: #007bff; /* Link color */
            text-decoration: none; 
        }

        a:hover {
            text-decoration: underline; /* Underline on hover */
        }
    </style>
</head>
<body>
    <!-- Top Bar -->
    <div class="top-bar">
        <img src="<?= $logoPath ?>" alt="TMO Logo" class="logo">  
        <h1 class="site-title">T.M.O Garden Shuttle Service</h1> 
        <div class="user-info">
            <h2 class="welcome-header">Welcome, <strong><?= htmlspecialchars($username); ?></strong> 🎉</h2>
            <button onclick="window.location.href='logout.php'" class="logout-button">
                <i class='bx bxs-log-out'></i> Log Out
            </button>
        </div>
    </div>

    <!-- Sidebar -->
    <aside class="sidebar">
        <nav class="sidebar-nav">
            <ul>
                <li>
                    <a href="index.php" class="active"><i class='bx bxs-dashboard'></i><span class="link-name">Dashboard</span></a>
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
                        <li><a href="manage_employee.php">Manage Employee</a></li>
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
            <h2>Deactivate Employee</h2>
            <form method="POST">
                <p>Are you sure you want to deactivate <?= htmlspecialchars($employee['firstName'] . " " . $employee['lastName']) ?>?</p>
                <button type="submit"><a href=""></a> Confirm Deactivation</button>
            </form>
            <a href="allemployee.php">Cancel</a>
        </div>
    </div>

    <script>
        // Toggle dropdown menus
        function toggleDropdown(menuId) {
            const dropdowns = document.querySelectorAll('.dropdown');
            dropdowns.forEach(dropdown => {
                if (dropdown.id !== menuId) {
                    dropdown.classList.remove('open');
                }
            });
            const clickedDropdown = document.getElementById(menuId);
            clickedDropdown.classList.toggle('open');
        }
    </script>
</body>
</html>