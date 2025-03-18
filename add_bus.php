<?php
include 'header.php';
require 'db.php'; // Include your database connection here

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $no = $_POST['no'];
    $plateNumber = $_POST['plateNumber'];
    $myFileNo = $_POST['myFileNo'];
    $motorNo = $_POST['motorNo'];
    $make = $_POST['make'];
    $chasisNo = $_POST['chasisNo'];
    $remarks = $_POST['remarks'];

    // Check if a bus with the same details already exists
    $checkStmt = $conn->prepare("SELECT COUNT(*) FROM buses WHERE no = ? OR plateNumber = ? OR myFileNo = ? OR motorNo = ? OR chasisNo = ?");
    $checkStmt->execute([$no, $plateNumber, $myFileNo, $motorNo, $chasisNo]);
    $exists = $checkStmt->fetchColumn();

    if ($exists > 0) {
        $errorMessage = " bus details already exists. Please check your inputs.";
    } else {
        $stmt = $conn->prepare("INSERT INTO buses (no, plateNumber, myFileNo, motorNo, make, chasisNo, remarks) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$no, $plateNumber, $myFileNo, $motorNo, $make, $chasisNo, $remarks]);
        
        header("Location: all_buses.php"); // Redirect to all_buses.php after addition
        exit();
    }
}

// Get username from the session for welcome message
$username = isset($_SESSION['username']) ? htmlspecialchars($_SESSION['username']) : 'Admin'; // Fallback to 'Admin'

// Path to your TMO logo image
$logoPath = '../tmo.jpg';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add Bus - TMO Shuttle Services</title>
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
            max-width: 600px; /* Maximum width for form container */
            margin: 3rem auto; /* Increase top margin to push the form down */
            padding: 2rem;
            background-color: #fff; /* Keep the form background white */
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
        input[type="text"] {
            width: 100%; /* Full width of the input */
            padding: 0.75rem; /* Padding */
            border: 1px solid #ced4da; /* Border color */
            border-radius: 0.25rem; /* Rounded corners */
            font-size: 1rem; /* Standard font size */
            transition: border-color 0.2s; /* Transition for border color */
            margin-bottom: 1rem; /* Margin at the bottom */
        }

        input[type="text"]:focus {
            border-color: #007bff; /* Border color on focus */
            outline: none; /* Remove outline */
        }

        /* Button Styles */
        button {
            background-color: #007bff; /* Primary button color */
            color: white; /* Button text color */
            padding: 0.75rem 1.5rem; /* Padding */
            border: none; /* No border */
            border-radius: 0.25rem; /* Rounded corners */
            font-size: 1rem; /* Standard font size */
            cursor: pointer; /* Pointer on hover */
            transition: background-color 0.2s, box-shadow 0.2s; /* Transitions */
            margin-right: 1rem; /* Space between buttons */
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
            <h2>Add Bus</h2>
            <?php if (isset($errorMessage)): ?>
                <p style="color: red;"><?= htmlspecialchars($errorMessage) ?></p>
            <?php endif; ?>
            <form method="POST" action="">
                <label for="no">Reference No:</label>
                <input type="text" id="no" name="no" required>

                <label for="plateNumber">Plate No:</label>
                <input type="text" id="plateNumber" name="plateNumber" required>

                <label for="myFileNo">My File No:</label>
                <input type="text" id="myFileNo" name="myFileNo" required>

                <label for="motorNo">Motor No:</label>
                <input type="text" id="motorNo" name="motorNo" required>

                <label for="make">Make:</label>
                <input type="text" id="make" name="make" required>

                <label for="chasisNo">Chasis No:</label>
                <input type="text" id="chasisNo" name="chasisNo" required>

                <label for="remarks">Remarks:</label>
                <input type="text" id="remarks" name="remarks">

                <button type="submit">Add Bus</button>
                <button type="button" class="back-button" onclick="window.history.back();">Cancel</button>
            </form>
        </div>
    </div>

    <script>
        // Hide all dropdowns by default
        document.querySelectorAll('.dropdown').forEach(dropdown => {
            dropdown.classList.remove('open'); // Start with dropdowns closed
        });
    </script>
</body>
</html>