Customer Portal API - Secure
A secure backend for a customer portal API, designed to handle international payments with robust security features. This project implements advanced security measures such as password hashing, input validation, SSL encryption, and protection against common web attacks. Continuous Integration and Code Quality Assurance are enforced using CircleCI and SonarCloud.

Features
•	Password Hashing: Utilizes Argon2 for secure password hashing with automatic salting.
•	Input Validation: Implements RegEx-based whitelisting for user inputs, ensuring protection against SQL injection and XSS attacks.
•	SSL/TLS Encryption: All data transmitted between clients and the server is secured using SSL certificates.
•	Protection Against Common Attacks:
o	DDoS protection with rate limiting
o	Cross-Site Request Forgery (CSRF) protection
o	Cross-Origin Resource Sharing (CORS) protection

•	Two-Factor Authentication (2FA): Adds an extra layer of security through time-based OTPs (One-Time Passwords).
•	Real-time Logging and Error Handling: Tracks errors and monitors requests to safeguard the platform.
•	Continuous Integration: Automated testing and code quality analysis using CircleCI and SonarCloud.
Getting Started

Prerequisites
•	Node.js: Make sure you have Node.js installed. You can download it here.
•	NPM: The Node package manager is required to install dependencies.
•	Git: Version control system required to clone the repository. You can download it here.

Installation
1.	Clone the repository:
git clone https://github.com/Sarutobikazuya3003/customer-portal-api-secure.git
2.	Navigate to the project directory:
cd customer-portal-api-secure/backend

3.	Install dependencies:
npm install

4.	Generate SSL certificates (for local testing):
openssl req -nodes -new -x509 -keyout key.pem -out cert.pem

5.	Run the server:
node index.js

API Endpoints
•	POST /register: Register a new user.
•	POST /login: Log in to receive a JWT token.
•	POST /2fa/setup: Set up two-factor authentication (2FA).
•	POST /2fa/verify: Verify the 2FA token.
•	GET /users: Get a list of all users (Admin only).
•	DELETE /users/:id: Delete a user (Admin only).

Environment Variables
Create a .env file in the project root to configure the following:
JWT_SECRET=your_jwt_secret
DB_CONNECTION=your_database_connection_string
PORT=5000

Testing
You can use Postman to test the API endpoints. Here’s how:
1.	Import the API collection: Download the Postman collection to quickly test all endpoints.
2.	Run the API tests: Use Postman to send requests to the provided endpoints and inspect the responses.
Two-Factor Authentication (2FA)
1.	When setting up 2FA, the server will return a secret key and a QR code.
2.	Use a QR code generator (such as this one) to convert the returned QR text into an image.
3.	Scan the QR code with Google Authenticator to get the TOTP (Time-based One-Time Password).
4.	Use the /2fa/verify endpoint to verify the TOTP and enable 2FA for your account.

Continuous Integration
The project uses CircleCI for Continuous Integration and SonarCloud for code quality analysis.
•	CircleCI: The pipeline runs automated tests on each push and ensures that the backend passes all checks.
•	SonarCloud: Code is continuously analyzed for security vulnerabilities, code smells, and other quality metrics.
You can view the pipeline here.

Contributing
If you’d like to contribute:
1.	Fork the repository.
2.	Create a new branch (git checkout -b feature/your-feature).
3.	Commit your changes (git commit -am 'Add your feature').
4.	Push to the branch (git push origin feature/your-feature).
5.	Open a pull request.

