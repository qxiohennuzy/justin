<?php
session_start(); // Start the session to access session variables

// Get Employee ID from the query string
$employeeId = isset($_GET['employeeId']) ? htmlspecialchars($_GET['employeeId']) : 'EMP12345';

// Get Attendance Data from the query string
$attendanceData = isset($_GET['attendanceData']) ? json_decode($_GET['attendanceData'], true) : [];

// Get Driver Name from the query string
$driverName = isset($_GET['driverName']) ? htmlspecialchars($_GET['driverName']) : 'Unknown Driver'; // Default name if not found

// Get Start and End Date from query string
$startDate = isset($_GET['startDate']) ? new DateTime($_GET['startDate']) : new DateTime();
$endDate = isset($_GET['endDate']) ? new DateTime($_GET['endDate']) : new DateTime();

// Get Days Attended from query string
$daysAttended = isset($_GET['daysAttended']) ? (int)$_GET['daysAttended'] : 0;

// Cap days at 30
if ($daysAttended > 30) {
    $daysAttended = 30;
}

// Other sample data
$department = "Transportation";
$dailyRate = 750; // Daily income

// Calculate gross pay
$grossPay = $dailyRate * $daysAttended;

// Check if the end date's day is less than or equal to 15 for deductions
$currentDay = (int)$endDate->format('d'); 

if ($currentDay <= 15) {
    // Deductions are applicable only on or before the 15th
    $sssContribution = 500; 
    $pagIbigContribution = 100; 
    $philHealthContribution = 300; 
} else {
    // No deductions after the 15th
    $sssContribution = 0; 
    $pagIbigContribution = 0; 
    $philHealthContribution = 0; 
}

// Total deductions
$totalDeductions = $sssContribution + $pagIbigContribution + $philHealthContribution;
$netPay = $grossPay - $totalDeductions;

// Format start and end date for display
$payPeriod = $startDate->format('F j, Y') . ' - ' . $endDate->format('F j, Y');

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Payslip - <?php echo htmlspecialchars($driverName); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Segoe+UI:wght@400;600&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa; /* Light gray background */
            color: #333;
            padding: 20px;
            max-width: 600px;
            margin: 0 auto;
            border: 1px solid #ccc;
            border-radius: 10px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }

        h1 {
            text-align: center;
            color: #007bff;
        }

        .details, .summary {
            margin-top: 20px;
            padding: 15px;
            background-color: #fff;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }

        .summary table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }

        .summary th, .summary td {
            border: 1px solid #ccc;
            padding: 8px;
            text-align: left;
        }

        .summary th {
            background-color: #f2f2f2;
        }

        .total {
            font-weight: bold;
            color: #007bff;
        }

        .footer {
            margin-top: 30px;
            text-align: center;
            font-size: 0.9em;
            color: gray;
        }

        .print-button {
            margin: 20px 0;
            padding: 10px 20px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.3s;
        }

        .print-button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>

    <h1>Payslip</h1>
    
    <div class="details">
        <strong>Driver Name:</strong> <span><?php echo htmlspecialchars($driverName); ?></span><br>
        <strong>Employee ID:</strong> <?php echo htmlspecialchars($employeeId); ?><br>
        <strong>Department:</strong> <?php echo htmlspecialchars($department); ?><br>
        <strong>Pay Period:</strong> <?php echo htmlspecialchars($payPeriod); ?><br>
        <strong>Days Attended:</strong> <?php echo htmlspecialchars($daysAttended); ?> out of 30 days<br>
    </div>

    <div class="summary">
        <h2>Summary</h2>
        <table>
            <thead>
                <tr>
                    <th>Description</th>
                    <th>Amount (PHP)</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Gross Pay (₱<?php echo number_format($dailyRate, 2); ?> x <?php echo $daysAttended; ?> days)</td>
                    <td>₱<?php echo number_format($grossPay, 2); ?></td>
                </tr>
                <tr>
                    <td>SSS Contribution</td>
                    <td>-₱<?php echo number_format($sssContribution, 2); ?></td>
                </tr>
                <tr>
                    <td>Pag-IBIG Contribution</td>
                    <td>-₱<?php echo number_format($pagIbigContribution, 2); ?></td>
                </tr>
                <tr>
                    <td>PhilHealth Contribution</td>
                    <td>-₱<?php echo number_format($philHealthContribution, 2); ?></td>
                </tr>
                <tr class="total">
                    <th>Total Deductions</th>
                    <th>-₱<?php echo number_format($totalDeductions, 2); ?></th>
                </tr>
                <tr class="total">
                    <th>Net Pay</th>
                    <th>₱<?php echo number_format($netPay, 2); ?></th>
                </tr>
            </tbody>
        </table>
    </div>

    <button class="print-button" onclick="window.print()">Print</button>

    <div class="footer">
        <p>This is an electronically generated payslip, no signature is required.</p>
    </div>
</body>
</html>