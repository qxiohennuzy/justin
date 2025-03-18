<?php
session_start(); // Start the session

// Include your database connection
require 'db.php'; 

// Initialize counts and set default values
$totalBookings = 0;
$totalBusesIn = 0;
$totalBusesOut = 0;
$currentMonth = date('Y-m');

// Fetch total number of buses
$stmt = $conn->query("SELECT COUNT(*) AS total FROM buses");
$totalBusCount = $stmt->fetchColumn();

// Fetch total number of active employees
$stmt = $conn->query("SELECT COUNT(*) AS total FROM employees WHERE isActive = 1");
$totalEmployeeCount = $stmt->fetchColumn();

// Count bookings for the current month
$stmt = $conn->prepare("SELECT COUNT(*) AS total FROM bookings WHERE DATE_FORMAT(date, '%Y-%m') = ?");
$stmt->execute([$currentMonth]);
$totalBookings = $stmt->fetchColumn();

// Count In/Out bookings for the current month
$stmt = $conn->prepare("SELECT in_out, COUNT(*) AS total FROM bookings WHERE DATE_FORMAT(date, '%Y-%m') = ? GROUP BY in_out");
$stmt->execute([$currentMonth]);
$inOutCounts = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);

$totalBusesIn = $inOutCounts['In'] ?? 0; // Set to 0 if 'In' is not found
$totalBusesOut = $inOutCounts['Out'] ?? 0; // Set to 0 if 'Out' is not found

// Define the logo path
$logoPath = './tmo.jpg'; // Adjust the path if necessary

// Fetch username from the session
$username = isset($_SESSION['username']) ? $_SESSION['username'] : 'Guest'; // Default to 'Guest' if not logged in
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <style>

 /* General Reset and Body Styles */
 * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f4f4f9; /* Soft light background */
            color: #333;
            display: flex;
            min-height: 100vh;
            overflow-x: hidden; 
            flex-direction: column; 
            padding-top: 80px; /* Adjust based on the height of your top bar */
        }

        /* Top Bar Styles */
        .top-bar {
            position: fixed; /* Make header fixed */
            top: 0; /* Stick it to the top of the viewport */
            left: 0; /* Align to the left */
            display: flex;
            align-items: center;
            justify-content: space-between; /* Positioning for logo and user info */
            padding: 1rem 1.5rem;
            background-color: #fff; /* Background color */
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
            width: 100%; /* Full width */
            z-index: 10; /* Above other content */
        }

        .logo {
            height: auto;       /* Maintain aspect ratio based on width */
            max-height: 80px;   /* Set maximum height to 80px */
            width: auto;        /* Maintain aspect ratio */
            max-width: 120px;   /* Set maximum width to 120px */
        }

        .title-container {
            flex-grow: 1; /* Allows the title to take available space */
            display: flex;
            justify-content: center; /* Center the title horizontally */
        }

        .site-title {
            position: absolute;
            left: 50%;
            transform: translateX(-50%);
            font-size: 1.5rem;
            color: #333;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .welcome-header {
            font-size: 1.5rem; 
            font-weight: 600; 
            color: #007bff; 
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

        .employees-list {
            margin-top: 100px; /* Space below the top bar */
            padding: 1rem 1.5rem;
        }

        .employees-list h2 {
            margin-bottom: 1rem;
        }

    </style>
</head>
<body>
   <!-- Top Bar -->
   <div class="top-bar">
       <img src="<?= htmlspecialchars($logoPath); ?>" alt="TMO Logo" class="logo">  
       <h1 class="site-title">T.M.O Garden Shuttle Service</h1> 
       <div class="user-info">
           <h2 class="welcome-header">Welcome, <strong><?= htmlspecialchars($username); ?></strong> 🎉</h2>
           <?php if(isset($_SESSION['username'])): ?>
               <button onclick="window.location.href='logout.php'" class="logout-button">
                   <i class='bx bxs-log-out'></i> Log Out
               </button>
           <?php endif; ?>
       </div>
   </div>

  