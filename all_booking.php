<?php
include 'header.php';
require 'db.php'; // Include your database connection
include 'sidebar.php';

// Prepare the SQL statement for fetching bookings
$stmt = $conn->query("SELECT * FROM bookings");
$allBookings = $stmt->fetchAll(PDO::FETCH_ASSOC);

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
    <title>All Bookings - TMO Shuttle Services</title>
    <link href="https://fonts.googleapis.com/css2?family=Segoe+UI:wght@400;600&display=swap" rel="stylesheet">
    <link href='https://unpkg.com/boxicons@2.1.4/css/boxicons.min.css' rel='stylesheet'>
    <style>
        /* Global Styles */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa; /* Soft light background for a fresh look */
            color: #333;
            display: flex;
            min-height: 100vh;
            overflow-x: hidden; /* Prevent horizontal overflow */
            flex-direction: column; /* Stack layout vertically */
        }

        /* Main Content Styles */
        .main-content {
            margin-left: 280px; /* Leave space for the sidebar */
            padding: 2rem; /* Padding for main content */
            flex-grow: 1; /* Allow this section to grow */
            background-color: #e9ecef; /* Background color for main content */
            border-radius: 8px; /* Rounded corners for a softer look */
        }

        h2 {
            text-align: left; /* Align header to the left */
            margin-bottom: 20px;
            color: #343a40; /* Darker color for headers */
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px; /* Margin below the table */
        }

        table, th, td {
            border: 1px solid #ccc;
            padding: 12px;
            text-align: left; /* Ensure all table content is left-aligned */
        }

        th {
            background: #f2f2f2; /* Light grey for headers */
            font-weight: bold;
        }

        .action-button {
            padding: 10px 15px; 
            cursor: pointer; 
            font-size: 14px; 
            margin-left: 5px; 
            background-color: #007BFF; 
            color: white; 
            border: none; 
            border-radius: 5px; 
            transition: background-color 0.3s; 
            text-decoration: none; /* No underline for action buttons */
        }

        .action-button:hover {
            background-color: #0056b3; 
        }

        .delete-button {
            background-color: #dc3545; /* Red for delete button */
        }

        .delete-button:hover {
            background-color: #c82333;
        }

        .search-container {
            margin-bottom: 20px;
            display: flex;
            justify-content: flex-start;
            align-items: center;
        }

        /* Modal Styles */
        .modal {
            display: none; /* Hidden by default */
            position: fixed; 
            z-index: 100; 
            left: 0;
            top: 0;
            width: 100%; 
            height: 100%; 
            overflow: auto; 
            background-color: rgba(0,0,0,0.4); /* Black w/ opacity */
            padding-top: 60px;
        }

        .modal-content {
            background-color: #fefefe;
            margin: 5% auto; 
            padding: 20px;
            border: 1px solid #888;
            width: 80%; /* Could be more or less, depending on screen size */
            max-width: 500px; /* Set a max width */
            border-radius: 8px; /* Rounded corners */
        }

        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
        }

        .close:hover,
        .close:focus {
            color: black;
            text-decoration: none;
            cursor: pointer;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            aside {
                width: 100%; /* Full width for sidebar */
                position: relative; /* Change position */
                height: auto; /* Auto height */
                padding-bottom: 1rem; /* Spacing */
                box-shadow: none; /* Remove shadow */
            }

            .main-content {
                margin-left: 0; /* Remove left margin */
                padding: 1rem; /* Adjust padding */
            }
        }
    </style>
</head>
<body>
  
    <div class="main-content">
        <h2>All Bookings</h2>
        <!-- Search Container -->
        <div class="search-container">
            <input type="text" id="searchInput" placeholder="Search bookings..." onkeyup="searchBookings()">
            <a href="add_booking.php">
                <button type="button" class="action-button">Add New Booking</button>
            </a>
            <button type="button" class="action-button" onclick="openTotalPriceModal()">Total Price</button>
        </div>
        
        <table id="bookingTable">
            <thead>
                <tr>
                    <th>No</th>
                    <th>Bus No</th>
                    <th>Driver Name</th>
                    <th>In/Out</th>
                    <th>Company</th>
                    <th>Date</th>
                    <th>Time</th>
                    <th>Seat No</th>
                    <th>Price</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($allBookings)): ?>
                    <tr><td colspan="10">No bookings found.</td></tr>
                <?php else: ?>
                    <?php foreach ($allBookings as $booking): ?>
                    <tr>
                        <td><?= htmlspecialchars($booking['id']) ?></td>
                        <td><?= htmlspecialchars($booking['busNo']) ?></td>
                        <td><?= htmlspecialchars($booking['driverName']) ?></td>
                        <td><?= htmlspecialchars($booking['in_out']) ?></td>
                        <td><?= htmlspecialchars($booking['company']) ?></td>
                        <td><?= htmlspecialchars($booking['date']) ?></td>
                        <td><?= htmlspecialchars(date('h:i A', strtotime($booking['time']))) ?></td>
                        <td><?= htmlspecialchars($booking['seatNo']) ?></td>
                        <td class="booking-price">₱<?= htmlspecialchars(number_format($booking['price'], 2)) ?></td> <!-- Changed here -->
                        <td>
                            <form action="edit_booking.php" method="GET" style="display:inline;">
                                <input type="hidden" name="id" value="<?= $booking['id'] ?>">
                                <button type="submit" class="action-button">Edit</button>
                            </form>

                            <form class="delete-form" data-id="<?= $booking['id'] ?>" style="display:inline;">
                                <input type="hidden" name="id" value="<?= $booking['id'] ?>">
                                <button type="button" class="action-button delete-button" 
                                        onclick="confirmDelete(this);">
                                    Delete
                                </button>
                            </form>
                            <a href="trip_ticket.php?id=<?= $booking['id'] ?>" class="action-button" style="text-decoration: none;">Print receipt</a>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- Modal for Displaying Total Price -->
    <div id="totalPriceModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeTotalPriceModal()">×</span>
            <h2>Select Date Range</h2>
            <label for="startDate">Start Date:</label>
            <input type="date" id="startDate" required>
            <label for="endDate">End Date:</label>
            <input type="date" id="endDate" required>
            <button type="button" class="action-button" onclick="calculateTotal()">Calculate Total Price</button>
            <div id="totalPriceDisplay" style="font-size: 1.5rem; text-align: center; margin-top: 10px;">Total Price: ₱0.00</div> <!-- Changed here -->
        </div>
    </div>

    <script>
        function toggleDropdown(menuId) {
            const dropdowns = document.querySelectorAll('.dropdown');
            dropdowns.forEach(dropdown => {
                if (dropdown.id !== menuId) {
                    dropdown.classList.remove('open'); // Close other dropdowns
                }
            });
            const clickedDropdown = document.getElementById(menuId);
            clickedDropdown.classList.toggle('open');
        }

        function searchBookings() {
            const input = document.getElementById('searchInput');
            const filter = input.value.toLowerCase();
            const table = document.getElementById('bookingTable');
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {
                const cells = rows[i].getElementsByTagName('td');
                let found = false;

                for (let j = 0; j < cells.length - 1; j++) {
                    if (cells[j].innerText.toLowerCase().includes(filter)) {
                        found = true;
                        break; // Break if a match is found
                    }
                }

                rows[i].style.display = found ? "" : "none"; // Show or hide rows
            }
        }

        function openTotalPriceModal() {
            document.getElementById('totalPriceModal').style.display = "block"; // Show the modal
            document.getElementById('totalPriceDisplay').textContent = 'Total Price: ₱0.00'; // Reset display
        }

        function closeTotalPriceModal() {
            document.getElementById('totalPriceModal').style.display = "none"; // Hide the modal
        }

        function calculateTotal() {
            const startDate = new Date(document.getElementById('startDate').value);
            const endDate = new Date(document.getElementById('endDate').value);
            const table = document.getElementById('bookingTable');
            const rows = table.getElementsByTagName('tr');
            let total = 0;

            if (isNaN(startDate) || isNaN(endDate) || startDate > endDate) {
                alert("Please select a valid date range.");
                return;
            }

            for (let i = 1; i < rows.length; i++) {
                const cells = rows[i].getElementsByTagName('td');
                const bookingDate = new Date(cells[5].textContent);
                if (rows[i].style.display !== "none" && bookingDate >= startDate && bookingDate <= endDate) {
                    const priceCell = cells[8];
                    total += parseFloat(priceCell.textContent.replace('₱', '').replace(',', '')) || 0; // Parse price correctly
                }
            }

            document.getElementById('totalPriceDisplay').textContent = `Total Price: ₱${total.toFixed(2)}`; // Changed here
        }

        window.onclick = function(event) {
            const modal = document.getElementById('totalPriceModal');
            if (event.target == modal) {
                closeTotalPriceModal();
            }
        }

        function confirmDelete(button) {
            const form = button.closest('.delete-form'); // Get the closest form
            const bookingId = form.getAttribute('data-id');

            if (confirm('Are you sure you want to delete this booking?')) {
                fetch('delete_booking.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'id=' + encodeURIComponent(bookingId)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Booking deleted successfully.');
                        // Remove the row from the table
                        form.closest('tr').remove();
                    } else {
                        alert('Error deleting booking: ' + data.error);
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred while deleting the booking.');
                });
            }
        }
    </script>
</body>
</html>