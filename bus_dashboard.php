<?php

require 'db.php'; // Include your database connection
include 'header.php';
include 'sidebar.php';

function fetchBuses($conn) {
    $stmt = $conn->query("SELECT * FROM buses");
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

$buses = fetchBuses($conn);

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
    <title>Bus Dashboard - TMO Shuttle Services</title>
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
            flex-direction: column; /* Stack elements vertically */
        }

    

        /* Main Content Styles */
        .main-content {
            margin-left: 280px; /* Leave space for the sidebar */
            padding: 2rem;
            flex-grow: 1;
            background-color: #e9ecef; /* Background color for main content */
        }

        h1 {
            text-align: center; /* Centered header */
            margin-bottom: 20px;
            color: #007bff;
        }

        .button-container {
            display: flex; /* Use Flexbox for horizontal layout */
            justify-content: center; /* Center buttons within the button container */
            gap: 1rem; /* Space between buttons */
            margin-bottom: 20px; /* Space below the button container */
        }

        button {
            padding: 10px 20px; 
            cursor: pointer; 
            background-color: #007BFF; 
            color: white; 
            border: none; 
            border-radius: 5px; 
            transition: background-color 0.3s; 
        }

        button:hover {
            background-color: #0056b3; 
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

            .button-container {
                flex-direction: column; /* Stack buttons on small screens */
                gap: 0.5rem; /* Space between buttons when stacked */
            }
        }

        @media print {
            body {
                background-color: white; /* Set a white background for print */
            }
            .top-bar, aside, .logout-button, .back-button, .print-button {
                display: none; /* Hide top bar, sidebar, buttons */
            }
            .main-content {
                margin-left: 0; /* Override the left margin */
                padding: 0; /* Remove padding */
            }
        }
    </style>
</head>
<body>

 
    <div class="main-content">

    <div class="logo-container" style="text-align: center; margin-bottom: 20px;">
            <img src="<?php echo $logoPath; ?>" alt="TMO Logo" style="max-width: 7.6%; height: auto;"> <!-- Logo set to normal size and responsive -->
        </div>

        <h1>Bus Dashboard</h1> <!-- Centered header -->


        <!-- Button container for horizontal alignment -->
        <div class="button-container">
            <button onclick="printDashboard()" class="print-button">Print Dashboard</button> <!-- Print button -->
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Reference No</th>
                    <th>Plate Number</th>
                    <th>My File No</th>
                    <th>Motor No</th>
                    <th>Make</th>
                    <th>Chasis No</th>
                    <th>Remarks</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($buses)): ?>
                    <tr><td colspan="7">No buses found.</td></tr>
                <?php else: ?>
                    <?php foreach ($buses as $bus): ?>
                    <tr>
                        <td><?= htmlspecialchars($bus['id']) ?></td>
                        <td><?php echo htmlspecialchars($bus['no']); ?></td>
                        <td><?php echo htmlspecialchars($bus['plateNumber']); ?></td>
                        <td><?php echo htmlspecialchars($bus['myFileNo']); ?></td>
                        <td><?php echo htmlspecialchars($bus['motorNo']); ?></td>
                        <td><?php echo htmlspecialchars($bus['make']); ?></td>
                        <td><?php echo htmlspecialchars($bus['chasisNo']); ?></td>
                        <td><?php echo htmlspecialchars($bus['remarks']); ?></td>
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
                if (dropdown.id !== menuId) {
                    dropdown.style.display = 'none'; // Hide other dropdowns
                }
            });
            const clickedDropdown = document.getElementById(menuId);
            clickedDropdown.style.display = clickedDropdown.style.display === 'block' ? 'none' : 'block'; // Toggle the current dropdown
        }
        
        function printDashboard() {
            window.print(); // Call print dialog
        }
    </script>
</body>
</html>