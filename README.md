# defense-mechanism
User Guide for Client-Server Application
Prerequisites
•	Ensure both the server and client executable files are present on the system.
•	The server should always be started before the client to allow proper connections.
•	Both server and client machines must be on the same network (e.g., Localhost).
Step-by-Step Walkthrough
Server Instructions
1.	Start the Server:
o	Double-click the server.exe file to launch the server application.
o	The application will display the status: Server Status: Stopped.
o	Click the Start Server button to start the server.
o	The status will change to Server Status: Running, and a message in the log area will indicate that the server is listening for connections.
o	If a log file(attack_logs.txt) is not present already, it will be created during the execution.
2.	Monitor Connections:
o	Any client attempting to connect will be logged in the scrollable text area.
o	Successful logins, failed attempts, or SQL injection attempts will be tracked here.
o	IP Blocking:
	If a client is blocked (e.g., due to brute force or SQL injection attempts), the log will mention the reason for the block.
3.	Stop the Server:
o	To stop the server, click the Stop Server button.
o	The status will revert to Server Status: Stopped.
o	The server will no longer accept new connections until restarted.
4.	Log File:
o	All server activities, including IP bans and login attempts, are logged in a file named attack_logs.txt.
o	Open this file with any text editor to view the server logs.

Client Instructions
1.	Start the Client:
o	Double-click the client.exe file to launch the client application.
o	The status will display: Status: Not Connected.
2.	Connect to the Server:
o	Click the Connect to Server button.
o	If the connection is successful, the status will change to Status: Connected, and a success message will appear.
3.	Enter the Password:
o	Enter the correct password (secure123 by default) in the password input field and click the Send Password button.
o	Successful Login:
	If the login is successful, the client window background will turn green, displaying a "Login Successful" message.
o	Failed Login:
	If the entered password is incorrect, the remaining attempts will be shown.
o	Blocked IP:
	If the IP is banned (e.g., due to SQL injection attempts or multiple failed logins), a message will indicate the block reason, and the connection will be terminated.
4.	Quit the Application:
o	To quit the client application, click the Quit button.

Notes
•	SQL Injection Protection:
o	The system detects malicious inputs like SQL injection keywords and immediately bans the IP.
•	Brute Force Prevention:
o	After 3 failed login attempts, the client’s IP is automatically banned.

Troubleshooting
•	“Connection Error” Message:
o	Ensure the server is running before connecting the client.
o	Verify that the client and server are using the same IP address and port.
•	Blocked IP:
o	If blocked due to malicious activity, you must unblock the IP from the server-side manually.
Bug Report and Known Issues
While the application is designed to ensure seamless and secure interaction between the client and server, the following bug has been identified:
Bug Description:
•	Issue: When the user enters the correct password (secure123 by default), the server logs the attempt as a "successful login," and the server-side application confirms the login. However, on the client side, it incorrectly displays a "Login Failed" message. This discrepancy prevents further interactions or actions after a successful login.
•	Impact: Users are unable to proceed with the application workflow, even after providing valid credentials.
Temporary Workaround:
1.	Verify that both server and client executables are running the latest version of the application.
2.	Restart both the server and the client and retry the login process.
3.	Check the server log file (attack_logs.txt) to confirm successful login attempts for validation.
Resolution Plan:
This bug is under active investigation. A patch can be made to ensure that successful login responses from the server are correctly interpreted and displayed on the client side. The overall application can be more refined to cover all the edge cases.

