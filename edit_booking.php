<?php
require 'db.php';
include 'header.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Retrieve form data
    $id = $_POST['id'];
    $busNo = $_POST['busNo'];
    $driverName = $_POST['driverName'];
    $inOut = $_POST['in_out'];
    $company = $_POST['company'];
    $date = $_POST['date'];
    $time = $_POST['time'];
    $price = $_POST['price'];
    $seatNo = $_POST['seatNo'];

    // Prepare and execute the update statement
    $stmt = $conn->prepare("UPDATE bookings SET busNo=?, driverName=?, in_out=?, company=?, date=?, time=?, price=?, seatNo=? WHERE id=?");
    if ($stmt->execute([$busNo, $driverName, $inOut, $company, $date, $time, $price, $seatNo, $id])) {
        header("Location: all_booking.php");
        exit();
    }
} else {
    $id = $_GET['id'];
    $stmt = $conn->prepare("SELECT * FROM bookings WHERE id = ?");
    $stmt->execute([$id]);
    $booking = $stmt->fetch(PDO::FETCH_ASSOC);
}


// Path to your TMO logo image
$logoPath = '../tmo.jpg';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Edit Booking - TMO Shuttle Services</title>
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
            height: calc(100vh - 60px); /* Adjust height to be full screen minus header height */
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
            display: none; /* Hide dropdown by default */
            padding-left: 10px; /* Indent for dropdown items */
        }

        /* Main Content Styles */
        .main-content {
            margin-left: 280px; /* Leave space for the sidebar */
            padding: 2rem; /* Padding for the main content area */
            flex-grow: 1; /* Allow this section to grow and fill available space */
            display: flex; /* Use flex layout */
            flex-direction: column; /* Stack child sections in a column */
            margin-top: 60px; /* Adjust margin for top bar */
            overflow-y: auto; /* Enable vertical scrolling if content overflows */
        }

        /* Form Container Styles */
        .container {
            max-width: 600px; /* Max width for the form */
            margin: 2rem auto;
            padding: 2rem;
            background-color: #fff; /* Keep form background white */
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
        input[type="text"], input[type="date"], input[type="time"], input[type="number"], select {
            width: 100%; /* Full width of the input */
            padding: 0.75rem; /* Consistent padding */
            border: 1px solid #ced4da; /* Border color */
            border-radius: 0.25rem; /* Rounded corners */
            font-size: 1rem; /* Standard font size */
            transition: border-color 0.2s; /* Transition for border color */
            margin-bottom: 1rem; /* Consistent margin at the bottom */
        }

        input[type="text"]:focus, input[type="date"]:focus, input[type="time"]:focus, input[type="number"]:focus, select:focus {
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
            transition: background-color 0.2s, box-shadow 0.2s; /* Transitions on hover */
            margin-right: 1rem; /* Space between buttons */
        }

        button:hover {
            background-color: #0056b3; /* Change color when hovered */
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.15); /* Shadow effect on hover */
        }

        /* Back Button Styles */
        .back-button {
            background-color: #dc3545; /* Danger color for back button */
        }

        .back-button:hover {
            background-color: #c82333; /* Change when hovered */
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
            <h2>Edit Booking</h2>
            <form method="POST" action="">
                <input type="hidden" name="id" value="<?= htmlspecialchars($booking['id']) ?>">
                
                <label for="busNo">Bus No:</label>
                <input type="text" id="busNo" name="busNo" value="<?= htmlspecialchars($booking['busNo']) ?>" required>

                <label for="driverName">Driver Name:</label>
                <input type="text" id="driverName" name="driverName" value="<?= htmlspecialchars($booking['driverName']) ?>" required>
                
                <label for="in_out">In/Out:</label>
                <select id="in_out" name="in_out" required>
                    <option value="In" <?= $booking['in_out'] == 'In' ? 'selected' : '' ?>>In</option>
                    <option value="Out" <?= $booking['in_out'] == 'Out' ? 'selected' : '' ?>>Out</option>
                </select>
                
                <label for="company">Company:</label>
                <select id="company" name="company" required>
                    <option value="<?= htmlspecialchars($booking['company']) ?>" selected><?= htmlspecialchars($booking['company']) ?></option>
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
                
                <label for="date">Date:</label>
                <input type="date" id="date" name="date" value="<?= htmlspecialchars($booking['date']) ?>" required>
                
                <label for="time">Time:</label>
                <input type="time" id="time" name="time" value="<?= htmlspecialchars($booking['time']) ?>" required>
                
                <label for="price">Price:</label>
                <input type="number" id="price" name="price" value="<?= htmlspecialchars($booking['price']) ?>" step="0.01" required>
                
                <label for="seatNo">Seat No:</label>
                <input type="text" id="seatNo" name="seatNo" value="<?= htmlspecialchars($booking['seatNo']) ?>" required>
                
                <button type="submit">Update Booking</button>
                <button type="button" class="back-button" onclick="window.history.back();">Back</button>
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