<?php
include 'header.php';
require 'db.php'; // Include your database connection

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $busNo = $_POST['busNo'];
    $driverName = $_POST['driverName'];
    $in_out = $_POST['in_out'];
    $company = $_POST['company'];
    $date = $_POST['date'];
    $time = $_POST['time'];
    $seatNo = $_POST['seatNo'];
    $price = $_POST['price'];

    // Check if the booking already exists
    $checkStmt = $conn->prepare("SELECT * FROM bookings WHERE busNo = ? AND driverName = ? AND in_out = ? AND company = ? AND date = ? AND time = ? AND seatNo = ? AND price = ?");
    $checkStmt->execute([$busNo, $driverName, $in_out, $company, $date, $time, $seatNo, $price]);

    if ($checkStmt->rowCount() > 0) {
        // Booking already exists
        $errorMessage = "Trip ticket already exists.";
    } else {
        // Proceed to insert the new booking
        $stmt = $conn->prepare("INSERT INTO bookings (busNo, driverName, in_out, company, date, time, seatNo, price) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$busNo, $driverName, $in_out, $company, $date, $time, $seatNo, $price]);

        header("Location: all_booking.php"); // Redirect after addition
        exit();
    }
}

// Get username from the session for welcome message
$username = isset($_SESSION['username']) ? htmlspecialchars($_SESSION['username']) : 'Admin'; // Fallback to 'Admin'
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add Booking - TMO Shuttle Services</title>
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
            flex-direction: column; /* Stack layout vertically */
        }

        /* Main Content Styles */
        .main-content {
            margin-left: 280px; /* Leave space for the sidebar */
            flex-grow: 1; /* Allow this section to grow */
            overflow-y: auto; /* Enable vertical scrolling if content overflows */
            display: flex; /* Use flex layout */
            flex-direction: column; /* Stack sections vertically */
        }

        /* Form Container Styles */
        .container {
            max-width: 500px; /* Reduced maximum width for form container */
            margin: 3rem auto; /* Increase top margin to push the form down */
            padding: 1.5rem; /* Reduced padding */
            background-color: #fff; /* Keep the form background white */
            border-radius: 0.25rem;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }

        /* Form Title */
        .container h2 {
            font-size: 1.5rem; /* Reduced font size */
            margin-bottom: 1rem; /* Reduced bottom margin */
            color: #007bff;
        }

        /* Form Labels */
        label {
            font-weight: 600;
            margin-bottom: 0.25rem; /* Reduced margin */
            display: block;
        }

        /* Form Input Styles */
        input[type="text"],
        input[type="date"],
        input[type="time"],
        select {
            width: 100%; /* Full width of the input */
            padding: 0.5rem; /* Reduced padding */
            border: 1px solid #ced4da; /* Border color */
            border-radius: 0.25rem; /* Rounded corners */
            font-size: 0.9rem; /* Reduced font size */
            transition: border-color 0.2s; /* Transition for border color */
            margin-bottom: 0.75rem; /* Reduced bottom margin */
        }

        input[type="text"]:focus,
        input[type="date"]:focus,
        input[type="time"]:focus,
        select:focus {
            border-color: #007bff; /* Border color on focus */
            outline: none; /* Remove outline */
        }

        /* Button Styles */
        button {
            background-color: #007bff; /* Primary button color */
            color: white; /* Button text color */
            padding: 0.5rem 1rem; /* Reduced padding */
            border: none; /* No border */
            border-radius: 0.25rem; /* Rounded corners */
            font-size: 0.9rem; /* Reduced font size */
            cursor: pointer; /* Pointer on hover */
            transition: background-color 0.2s, box-shadow 0.2s; /* Transitions */
            margin-right: 0.5rem; /* Reduced space between buttons */
        }

        button:hover {
            background-color: #0056b3; /* Change color when hovered */
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.15); /* Shadow effect on hover */
        }

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
    <?php include 'sidebar.php'; ?>
    <div class="main-content">
        <div class="container">
            <h2>Add Booking</h2>
            <?php if (isset($errorMessage)): ?>
                <div style="color: red; margin-bottom: 1rem;"><?php echo htmlspecialchars($errorMessage); ?></div>
            <?php endif; ?>
            <form method="POST" action="">
                <label for="busNo">Bus No:</label>
                <input type="text" id="busNo" name="busNo" required>

                <label for="driverName">Driver Name:</label>
                <input type="text" id="driverName" name="driverName" required>

                <label for="in_out">In/Out:</label>
                <select id="in_out" name="in_out" required>
                    <option value="" disabled selected>Select In/Out</option>
                    <option value="In">In</option>
                    <option value="Out">Out</option>
                </select>

                <label for="company">Company:</label>
                <select id="company" name="company" required>
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
                <input type="date" id="date" name="date" required>

                <label for="time">Time:</label>
                <input type="time" id="time" name="time" required>

                <label for="seatNo">Seat No:</label>
                <input type="text" id="seatNo" name="seatNo" required>

                <label for="price">Price:</label>
                <input type="text" id="price" name="price" required>

                <button type="submit">Add Booking</button>
                <button type="button" class="back-button" onclick="window.history.back();">Cancel</button>
            </form>
        </div>
    </div>

    <script>
        // Your existing JavaScript logic here, if any
    </script>
</body>
</html>