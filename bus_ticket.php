<?php
include 'header.php';
require 'db.php'; // Include your database connection

// Assuming this data would be fetched or passed after adding a booking.
// Initialize variables if coming from a previous form submission.
$busNo = $_POST['busNo'] ?? '';
$driverName = $_POST['driverName'] ?? '';
$inOut = $_POST['in_out'] ?? '';
$company = $_POST['company'] ?? '';
$date = $_POST['date'] ?? '';
$time = $_POST['time'] ?? '';
$price = $_POST['price'] ?? '';
$seatNo = $_POST['seatNo'] ?? '';

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
    <title>Bus Ticket - TMO Shuttle Services</title>
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
            border-left: 3px solid transparent;
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
            display: none; /* Hide dropdowns by default */
            padding-left: 20px; /* Indent dropdown items */
        }

        .dropdown.open {
            display: block; /* Show dropdown when 'open' class is added */
        }

        /* Main Content Styles */
        .main-content {
            margin-left: 280px; /* Leave space for the sidebar */
            flex-grow: 1; /* Allow this section to grow and fill available space */
            overflow-y: auto; /* Enable vertical scrolling if content overflows */
            display: flex; /* Use flex layout */
            flex-direction: column; /* Stack child sections in a column */
            align-items: center; /* Center content horizontally */
            padding: 1rem; /* Padding for the main content area */
            background-color: #e9ecef; /* Background color for main content */
        }

        /* Ticket Styles */
        .ticket {
            border: 1px solid #ddd; /* Lighter border */
            padding: 20px;
            width: 100%;            /* Full width for crosswise */
            max-width: 793px;      /* Max width for half a letter-sized page */
            height: auto;          /* Height adjustable automatically */
            background-color: #ffffff; /* White background for the ticket */
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1); /* Subtle shadow */
            border-radius: 12px;      /* More rounded corners */
            text-align: center;       /* Center align text */
            margin: 20px 0;          /* Center the ticket and space above and below */
        }

        h1 {
            font-size: 20px; /* Adjust font size to fit better */
            color: #4CAF50; /* Green color */
            margin: 0;
            padding-bottom: 10px; /* Space between the title and logo */
        }

        h2 {
            font-size: 18px; /* Adjust font size for subtitle */
            color: #333; /* Darker text for contrast */
            margin: 0; 
            margin-bottom: 15px; /* Space below the subtitle */
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;        /* Space above the table */
        }

        th, td {
            border: 1px solid #ddd; /* Use a lighter color for borders */
            padding: 5px;           /* Padding for better readability */
            text-align: left;
            font-size: 14px; /* Adjust font size for table text */
        }

        th {
            background-color: #f7f7f7; /* Light gray background */
            color: #333; /* Darker font */
            font-weight: 600; /* Bolder headings */
        }

        .signature {
            margin-top: 20px;        /* Space above signature area */
            border-top: 2px dashed #4CAF50; /* Dashed line for signature */
            padding-top: 10px;       /* Spacing inside signature area */
            color: #777; /* Placeholder text color */
            font-size: 14px; /* Adjust font size for signature text */
        }

        .print-button {
            margin: 20px; /* Space around the button */
            padding: 10px 20px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s;
        }

        .print-button:hover {
            background-color: #0056b3; /* Darker blue on hover */
        }

        @media print {
            .top-bar, aside, .print-button { 
                display: none; /* Hidden when printing */
            }
            .main-content {
                padding: 0; /* Remove padding for print view */
                margin: 0; /* Remove margin for print view */
            }
            .ticket {
                box-shadow: none; /* Remove shadow in print view */
                border: none; /* Remove border in print view */
                margin: 0; /* Make the ticket full width for print */
                height: auto; /* Let height adjust automatically */
        
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
                        <li><a href="bin.php">Manage Employees</a></li>
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
                        <li><a href="bus_dashboard.php">Bus Management Report</a></li>
                        <li><a href="booking_dashboard.php">Scheduling Report</a></li>
                    </ul>
                </li>
            </ul>
        </nav>
    </aside>

    <div class="main-content">
        <!-- Ticket Display -->
        <div class="ticket">
            <img src="<?= $logoPath ?>" alt="Company Logo" style="width: 15%; height: auto;">
            <h1>T.M.O Garden Shuttle Service</h1>
            <h2>Bus Ticket</h2>
            
            <table>
                <tr>
                    <th>Details</th>
                    <th>Information</th>
                </tr>
                <tr>
                    <td>Company assigned</td>
                    <td><?= htmlspecialchars($company); ?></td>
                </tr>
                <tr>
                    <td>Date</td>
                    <td><?= htmlspecialchars($date); ?></td>
                </tr>
                <tr>
                    <td>Driver Name</td>
                    <td><?= htmlspecialchars($driverName); ?></td>
                </tr>
                <tr>
                    <td>Bus Reference No</td>
                    <td><?= htmlspecialchars($busNo); ?></td>
                </tr>
                <tr>
                    <td>In/Out</td>
                    <td><?= htmlspecialchars($inOut); ?></td>
                </tr>
                <tr>
                    <td>Time</td>
                    <td><?= htmlspecialchars($time); ?></td>
                </tr>
                <tr>
                    <td>Seat Number</td>
                    <td><?= htmlspecialchars($seatNo); ?></td>
                </tr>
                <tr>
                    <td>Price</td>
                    <td><?= htmlspecialchars($price); ?></td>
                </tr>
            </table>

            <div class="signature">
                <p>Please sign below:</p>
                <div style="height: 20px; border-top: 1px solid #000; margin-top: 5px;"></div>
                <p>(Signature)</p>
            </div>
        </div>

        <!-- Print Button -->
        <button class="print-button" onclick="printTicket()">Print Ticket</button>

        <!-- Back to Main Menu Button -->
        <button class="print-button" onclick="window.location.href='index.php'">Back to Main Menu</button>
    </div>

    <script>
        let lastOpenedDropdown = null;

        function toggleDropdown(dropdownId) {
            const dropdown = document.getElementById(dropdownId);

            // If the clicked dropdown is already open, close it
            if (dropdown === lastOpenedDropdown) {
                dropdown.classList.remove('open');
                lastOpenedDropdown = null;
            } else {
                // Close the last opened dropdown if it's different
                if (lastOpenedDropdown) {
                    lastOpenedDropdown.classList.remove('open');
                }
                // Open the current dropdown
                dropdown.classList.add('open');
                lastOpenedDropdown = dropdown;
            }
        }

        // Set active link based on the current URL
        document.querySelectorAll('aside a').forEach(link => {
            if (link.href === window.location.href) {
                link.classList.add('active');
            }
        });
    </script>
</body>
</html>