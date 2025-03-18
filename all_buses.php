<?php
include 'header.php';
require 'db.php'; // Include your database connection here
include 'sidebar.php';

// Fetch all buses
$stmt = $conn->query("SELECT * FROM buses");
$buses = $stmt->fetchAll();

// Get username from the session for the welcome message
$username = isset($_SESSION['username']) ? htmlspecialchars($_SESSION['username']) : 'Admin';

// Path to your TMO logo image
$logoPath = './tmo.jpg';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>All Buses - TMO Shuttle Services</title>
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
            background-color: #f8f9fa;
            color: #333;
            display: flex;
            min-height: 100vh;
            overflow-x: hidden; /* Prevent horizontal overflow */
        }

     

        .main-content {
            margin-left: 280px; /* Leave space for the sidebar */
            padding: 2rem;
            flex-grow: 1;
            background-color: #e9ecef; /* Background color for main content */
        }

        h2 {
            margin-bottom: 20px;
            text-align: left; /* Align title to the left */
        }

        .container {
            width: 100%;
            max-width: 1800px;
            padding: 0 15px;
            text-align: left; /* Ensure container text is aligned to left */
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }

        table, th, td {
            border: 1px solid #ccc;
            padding: 10px;
            text-align: left; /* Align table cells to the left */
        }

        th {
            background: #f2f2f2;
        }

        .search-container {
            margin-bottom: 20px;
            display: flex;
            justify-content: flex-start;
            align-items: center;
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
            background-color: #007BFF; 
            color: white; 
            border: none; 
            border-radius: 4px; 
            transition: background-color 0.3s; 
            text-decoration: none; /* Remove underline */
            display: inline-block; /* Make button-like */
        }

        .action-button:hover {
            background-color: #0056b3; 
        }

        .delete-button {
            background-color: #dc3545; /* Danger color for delete button */
        }

        .delete-button:hover {
            background-color: #c82333; /* Darker red for hover */
        }

        /* Responsive Design */
        @media (max-width: 600px) {
            body, table {
                width: 90%;
                margin: 0 auto; /* Center the content */
            }

            th, td {
                font-size: 14px; /* Resize table font on smaller screens */
            }
        }
    </style>
</head>
<body>
   

   
    <div class="main-content">
        <div class="container">
            <h2>All Buses</h2>

            <div class="search-container">
                <input type="text" id="searchInput" placeholder="Search Buses..." onkeyup="searchBuses()" style="margin-right: 8px;">
                <div style="display: flex;">
                    <a href="add_bus.php">
                        <button type="button" class="action-button">Add Bus</button>
                    </a>
                  
                </div>
            </div>

            <table id="busTable">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Reference No</th>
                        <th>Plate Number</th>
                        <th>My File No</th>
                        <th>Motor No</th>
                        <th>Make</th>
                        <th>Chassis No</th>
                        <th>Remarks</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($buses as $bus): ?>
                    <tr>
                        <td><?= htmlspecialchars($bus['id']) ?></td>
                        <td><?= htmlspecialchars($bus['no']) ?></td>
                        <td><?= htmlspecialchars($bus['plateNumber']) ?></td>
                        <td><?= htmlspecialchars($bus['myFileNo']) ?></td>
                        <td><?= htmlspecialchars($bus['motorNo']) ?></td>
                        <td><?= htmlspecialchars($bus['make']) ?></td>
                        <td><?= htmlspecialchars($bus['chasisNo']) ?></td>
                        <td><?= htmlspecialchars($bus['remarks']) ?></td>
                        <td>
                            <a href="edit_bus.php?id=<?= $bus['id'] ?>" class="action-button">Edit</a>
                            <a href="delete_bus.php?id=<?= $bus['id'] ?>" class="action-button delete-button">Delete</a>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
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

        function searchBuses() {
            const input = document.getElementById('searchInput');
            const filter = input.value.toLowerCase();
            const table = document.getElementById('busTable');
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {
                const cells = rows[i].getElementsByTagName('td');
                let found = false;

                for (let j = 0; j < cells.length - 1; j++) { // Excluding the last cell with actions
                    if (cells[j].innerText.toLowerCase().includes(filter)) {
                        found = true;
                        break; // Break if a match is found
                    }
                }

                rows[i].style.display = found ? "" : "none"; // Show or hide rows
            }
        }

        // Hide all dropdowns by default
        document.querySelectorAll('.dropdown').forEach(dropdown => {
            dropdown.style.display = 'none';
        });
    </script>
</body>
</html>