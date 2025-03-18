<?php

require 'db.php'; // Include your database connection

// Check if booking ID is provided
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    die("Invalid Booking ID.");
}

// Fetch the details of the specified booking
try {
    $stmt = $conn->prepare("SELECT * FROM bookings WHERE id = :id");
    $stmt->bindParam(':id', $_GET['id'], PDO::PARAM_INT);
    $stmt->execute();
    $booking = $stmt->fetch(PDO::FETCH_ASSOC);

    // If no booking is found, show an error message
    if (!$booking) {
        die("No booking found for the given ID.");
    }
} catch (PDOException $e) {
    die("Database error: " . $e->getMessage());
}

// Path to your TMO logo image
$logoPath = './tmo.jpg';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trip Ticket - TMO Shuttle Services</title>
    <link href="https://fonts.googleapis.com/css2?family=Segoe+UI:wght@400;600&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f0f4f8; /* Light background for overall page */
            color: #333;
            margin: 0;
        }

        .receipt {
            background-color: #fff;
            border: 1px solid #eaeaea; /* Light border for distinction */
            border-radius: 8px;
            padding: 30px;
            width: 100%;
            max-width: 600px; /* A bit wider for better aesthetics */
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            margin: 40px auto; /* Center receipt on the page */
            text-align: left;
            font-size: 14px; /* Standard font size */
        }

        .header {
            text-align: center; /* Center align header content */
            margin-bottom: 20px; /* Increased space below the header */
        }

        .logo img {
            height: 100px; /* Slightly larger logo */
            margin-bottom: 10px; /* Space below logo */
        }

        .header-title {
            font-size: 22px; /* Larger title font */
            font-weight: bold;
            color: #0056b3; /* Brand color for title */
            margin-bottom: 5px; /* Space below title */
        }

        .address {
            font-size: 14px; /* Slightly smaller font for address */
            color: #777; /* Muted color */
        }

        h1 {
            text-align: center;
            font-size: 24px; /* Larger and bolder title for receipt */
            margin: 20px 0;
            color: #333;
        }

        .receipt-header {
            text-align: center;
            font-size: 18px; /* Increased font size */
            color: #0056b3; /* Brand color */
            font-weight: bold;
            margin: 10px 0;
            text-transform: uppercase;
            border-bottom: 2px solid #0056b3; /* Emphasized line */
            padding-bottom: 5px; /* Padding under the line */
        }

        .booking-id {
            text-align: center; /* Center the booking ID */
            font-size: 16px;
            margin-bottom: 20px; /* Space below Booking ID */
            color: #333;
            /* Removed margin-left to ensure centering */
        }

        .details {
            margin-bottom: 20px;
        }

        .info-line {
            display: flex;
            justify-content: space-between;
            border-bottom: 1px solid #ccc; /* Separator line for each line item */
            padding: 10px 0; /* Spacing for each line */
        }

        .info-line span {
            flex: 1;
            text-align: left;
            color: #555; /* Muted text color */
        }

        .trip-info {
            display: flex;
            justify-content: space-between;
            border-top: 1px solid #0056b3; /* Top border to separate sections */
            margin: 20px 0;
            padding-top: 10px; /* Space above this section */
        }

        .footer {
            text-align: center;
            margin-top: 20px;
            font-size: 14px; /* Smaller font for footer */
            color: #777; /* Muted footer text */
            border-top: 1px solid #eaeaea; /* Top border */
            padding-top: 15px; /* Padding above footer */
        }

        .signature {
            margin-top: 20px;
            text-align: right;
            font-size: 14px; /* Signature font size */
            color: #777; /* Muted color for signature */
        }

        .signature-line {
            border-top: 1px solid #000; /* Solid line for signature area */
            width: 250px;
            margin: 10px auto; /* Center the line */
            text-align: center; /* Center the placeholder text */
            padding-top: 5px;
        }

        .back-button {
            display: inline-block;
            margin: 20px auto; /* Center the button horizontally */
            padding: 10px 20px; /* Enhanced padding for aesthetics */
            background-color: #0056b3; /* Brand color */
            color: white;
            font-size: 16px; /* Standard button font */
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            text-align: center; /* Center text */
            transition: background-color 0.3s;
        }

        .back-button:hover {
            background-color: #004494; /* Darker blue on hover */
        }

        @media print {
            body {
                background-color: #fff; /* Remove background on print */
            }

            .receipt {
                box-shadow: none; /* Remove shadow in print */
                border: none; /* Remove border in print */
                margin: 0; /* Remove margin for a better print-fit */
                max-width: 100%; /* Extend to full width for printing */
                padding: 20px; /* Adjust padding for print */
                background-color: red;
                color: #0056b3;
            }

            .back-button {
                display: none; /* Hide back button when printing */
            }

            h1, .header-title, .receipt-header {
                font-size: 20px; /* Adjust font sizes for better readability in print */
            }

            .info-line span {
                text-align: left; /* Ensure text alignment is left for all lines */
                font-size: 14px; /* Consistent font size for print */
            }

            .footer, .signature {
                font-size: 12px; /* Smaller footer text for printing */
            }
        }
    </style>
</head>
<body>

    <div class="receipt">
        <div class="header">
            <div class="logo">
                <img src="<?= htmlspecialchars($logoPath) ?>" alt="TMO Logo">
            </div>
            <div class="header-title">T.M.O Garden Shuttle Service</div>
            <div class="address">Barangay Pagaspas, Tanauan, Philippines</div>
        </div>
        
        <div class="receipt-header">
            <strong>Trip Reciept</strong>
        </div>
        
        <div class="booking-id">No: <strong><?= htmlspecialchars($booking['id']); ?></strong></div> <!-- Centered Booking ID -->
        
        <div class="trip-info">
            <div>
                <strong>Driver Name:</strong><br>
                <?= htmlspecialchars($booking['driverName']); ?>
            </div>
            <div>
                <strong>Company:</strong><br>
                <?= htmlspecialchars($booking['company']); ?>
            </div>
            <div>
                <strong>Bus Reference No:</strong><br>
                <?= htmlspecialchars($booking['busNo']); ?>
            </div>
        </div>
        
        <div class="details">
            <div class="info-line">
                <span>Seat No:</span>
                <span><?= htmlspecialchars($booking['seatNo']); ?></span>
            </div>
            <div class="info-line">
                <span>In/Out:</span>
                <span><?= htmlspecialchars($booking['in_out']); ?></span>
            </div>
            <div class="info-line">
                <span>Date:</span>
                <span><?= htmlspecialchars($booking['date']); ?></span>
            </div>
            <div class="info-line">
                <span>Time:</span>
                <span><?= htmlspecialchars($booking['time']); ?></span>
            </div>
            <div class="info-line">
                <span>Price:</span>
                <span>₱<?= htmlspecialchars($booking['price']); ?></span>
            </div>
        </div>
        
        <div class="footer">
            <p>Thank you for choosing T.M.O Shuttle Services!</p>
            <div class="signature">
                <div class="signature-line">Signature</div>
            </div>
        </div>
        
        <!-- Back Button -->
        <button class="back-button" onclick="window.history.back();">Back to the Page</button>
    </div>

    <script>
        window.onload = function() {
            window.print(); // Automatically trigger print on page load
        };
    </script>

</body>
</html>