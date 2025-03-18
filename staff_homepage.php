<?php

require 'db.php'; // Include your database connection
include 'header.php'; // Include header

// Initialize counts and queries as described before
$totalBookings = 0;
$totalBusesIn = 0;
$totalBusesOut = 0;

// Set the current month by default
$currentMonth = date('Y-m');

// Count total number of buses
$stmt = $conn->query("SELECT COUNT(*) AS total FROM buses");
$totalBusCount = $stmt->fetchColumn(); // Get the total count of buses

// Count total number of active employees only
$stmt = $conn->query("SELECT COUNT(*) AS total FROM employees WHERE isActive = 1");
$totalEmployeeCount = $stmt->fetchColumn(); // Get the total count of active employees

// Count bookings for the current month
$stmt = $conn->prepare("SELECT COUNT(*) AS total FROM bookings WHERE DATE_FORMAT(date, '%Y-%m') = ?");
$stmt->execute([$currentMonth]);
$totalBookings = $stmt->fetchColumn(); // Get the total count of bookings for the current month

// In/Out bookings counts
$stmt = $conn->prepare("SELECT in_out, COUNT(*) AS total FROM bookings WHERE DATE_FORMAT(date, '%Y-%m') = ? GROUP BY in_out");
$stmt->execute([$currentMonth]);
$inOutCounts = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);

$totalBusesIn = $inOutCounts['In'] ?? 0;
$totalBusesOut = $inOutCounts['Out'] ?? 0;

// Path to your TMO logo image
$logoPath = '../tmo.jpg'; // Adjust the path if necessary
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TMO Shuttle Services - Admin Homepage</title>
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
            height: calc(100vh - 60px); /* Adjust height */
            position: fixed;
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
            padding-left: 10px; /* Indent for dropdown items */
        }

        .dropdown.open {
            display: block; /* Show dropdown when class 'open' is added */
        }

        /* Main Content Styles */
        .main-content {
            background-color: #e9ecef; /* Background color for main content */
            margin-left: 280px; /* Leave space for the sidebar */
            flex-grow: 1; /* Allow this section to grow and fill available space */
            overflow-y: auto; /* Enable vertical scrolling if content overflows */
            display: flex; /* Use flex layout */
            flex-direction: column; /* Stack sections in a column */
            margin-top: 0; /* Remove top margin for the dashboard */
        }

        /* Content Section Styles */
        .content-section {
            flex: 1; /* Allow it to grow and fill remaining space */
            background-color: #ffffff; /* White background */
            border-radius: 0.25rem;
            padding: 2rem; /* Adjust padding for content area instead of using margin */
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            margin-top: 0; /* Ensure there is no top margin for the content section */
        }

        .welcome-section {
            margin-bottom: 1rem; /* Space below welcome section */
        }

        .welcome-section h2 {
            font-size: 2rem;
            margin: 0; /* Remove default margins */
        }

        /* Stats Styles */
        .stats {
            display: flex;
            justify-content: space-between; /* Space out items evenly */
            flex-wrap: wrap; /* Allow items to wrap on smaller screens */
            margin-top: 1.5rem; /* Margin above stats section */
            width: 100%;
        }

        .stat-card {
            background-color: #e9ecef; /* Subtle card color */
            border-radius: 0.25rem;
            flex: 1 1 200px; /* Allow flexibility */
            margin: 0.5rem; /* Margin around cards */
            padding: 1.5rem;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
        }

        .stat-card i {
            font-size: 2.5rem;
            color: #007bff;
            margin-bottom: 0.5rem;
        }

        .stat-card p {
            font-size: 1.3rem;
            font-weight: 600;
            color: #495057;
        }
    </style>
</head>
<body>
    <div class="main-content">
        <!-- Overview Section -->
        <div id="overview" class="content-section">
            <div class="welcome-section">
                <h2>Dashboard</h2>
            </div>

            <div class="stats">
                <div class="stat-card">
                    <i class='bx bxs-bus'></i>
                    <p id="total-products"><?= htmlspecialchars($totalBusCount); ?></p>
                    <span>Total Buses</span>
                </div>
                <div class="stat-card">
                    <i class='bx bxs-check-circle'></i>
                    <p id="total-buses-in"><?= htmlspecialchars($totalBusesIn); ?></p>
                    <span>Total Buses In</span>
                </div>
                <div class="stat-card">
                    <i class='bx bxs-x-circle'></i>
                    <p id="total-buses-out"><?= htmlspecialchars($totalBusesOut); ?></p>
                    <span>Total Buses Out</span>
                </div>
              
                <div class="stat-card">
                    <i class='bx bxs-book'></i>
                    <p id="total-bookings"><?= htmlspecialchars($totalBookings); ?></p>
                    <span>Total Bookings</span>
                </div>
            </div>
        </div>
    </div>

    <!-- Sidebar -->
    <aside class="sidebar" role="navigation" aria-label="Main Navigation">
        <nav class="sidebar-nav">
            <ul>
                <li>
                    <a href="#" class="active" onclick="showSection('overview')" role="link" aria-current="page"><i class='bx bxs-dashboard'></i><span class="link-name">Dashboard</span></a>
                </li>
                <li>
                    <a href="javascript:void(0)" onclick="toggleDropdown('busManagement')" role="button" aria-expanded="false" aria-controls="busManagement"><i class='bx bxs-bus'></i> Bus Management</a>
                    <ul id="busManagement" class="dropdown" aria-hidden="true">
                        <li><a href="add_bus.php" role="link">Add Bus</a></li>
                        <li><a href="all_buses.php" role="link">All Buses</a></li>
                    </ul>
                </li>
             
                <li>
                    <a href="javascript:void(0)" onclick="toggleDropdown('schedulingManagement')" role="button" aria-expanded="false" aria-controls="schedulingManagement"><i class='bx bxs-calendar'></i> Scheduling</a>
                    <ul id="schedulingManagement" class="dropdown" aria-hidden="true">
                        <li><a href="add_booking.php" role="link">Add Booking</a></li>
                        <li><a href="all_booking.php" role="link">All Bookings</a></li>
                        <li><a href="bus_ticket.php" role="link">Print Trip Ticket</a></li>
                    </ul>
                </li>
                <li>
                    <a href="javascript:void(0)" onclick="toggleDropdown('reportsManagement')" role="button" aria-expanded="false" aria-controls="reportsManagement"><i class='bx bxs-report'></i> All Reports</a>
                    <ul id="reportsManagement" class="dropdown" aria-hidden="true">
                        <li><a href="employee_dashboard.php" role="link">Employee Report</a></li>
                        <li><a href="booking_dashboard.php" role="link">Scheduling Report</a></li>
                        <li><a href="bus_dashboard.php" role="link">Bus Management Report</a></li>
                    </ul>
                </li>
            </ul>
        </nav>
    </aside>

    <script>
        function toggleDropdown(menuId) {
            // Close other dropdowns
            const dropdowns = document.querySelectorAll('.dropdown');
            dropdowns.forEach(dropdown => {
                if (dropdown.id !== menuId) {
                    dropdown.classList.remove('open'); // Close other dropdowns
                    dropdown.setAttribute('aria-hidden', 'true'); // Set aria-hidden attribute
                }
            });

            // Toggle the clicked dropdown
            const clickedDropdown = document.getElementById(menuId);
            const isOpen = clickedDropdown.classList.toggle('open');
            clickedDropdown.setAttribute('aria-hidden', !isOpen); // Set aria-hidden based on toggle state
        }

        // Check if it's the start of a new month and refresh the page
        function checkAndRefreshForNewMonth() {
            const lastVisit = localStorage.getItem('lastVisit');
            const currentDate = new Date();
            const currentMonth = currentDate.getMonth();
            const currentYear = currentDate.getFullYear();

            // If lastVisit is not set or last visit month/year is different, reload the page
            if (!lastVisit || new Date(lastVisit).getMonth() !== currentMonth || new Date(lastVisit).getFullYear() !== currentYear) {
                localStorage.setItem('lastVisit', currentDate.toISOString());
                window.location.reload(); // Refresh the page
            }
        }

        window.onload = checkAndRefreshForNewMonth; // Run the check when the page loads
    </script>
</body>
</html>