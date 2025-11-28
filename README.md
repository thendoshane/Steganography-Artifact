## Master's Thesis Artifact: Steganography Tool
-    This is a continuous project that gets updated after each thesis phase and not fully functional
-    All rights are reserved and associated with the University of Johannesburg insitution
## Academic Context
Degree: Master of Science in Computer Science

Institution: University of Johannesburg (UJ)

Author: Thendo Shane

Repository Status: Active Artifact

This repository contains the practical software artifact developed for my Master's thesis. The project implements advanced digital steganography techniques within a modern web application framework, demonstrating the practical application of the theoretical concepts discussed in the dissertation.

## Live Demo
The application is deployed and accessible for testing at:

👉 https://steganography-artifact.vercel.app

## Project Overview
This tool is designed to demonstrate secure data concealment. It provides a user-friendly interface for embedding (encoding) and extracting (decoding) hidden information within digital media files. The artifact serves to validate the efficacy, robustness, and imperceptibility of the steganographic algorithms researched during the study.

## Key Features
- Web-Based Interface: Accessible via any standard web browser without complex local installation.
- Encoding Module: Allows users to hide payload data within cover media.
- Decoding Module: Enables the extraction of hidden data from steganographic media.
- Algorithm Implementation: Demonstrates the application of specific steganographic algorithms [You can verify if it's LSB, DCT, etc. and add it here].

## Technical Architecture
The application is built using a modern full-stack JavaScript architecture:

- Frontend: React.js (Bootstrapped with Create React App)
- Backend: Node.js / Express (handled via server.js and api/ directory)
- Deployment: Vercel & Firebase

## Installation & Local Development
To run this project locally for inspection or grading purposes, follow these steps:

## Prerequisites
- Node.js (v14 or higher recommended)
- npm (Node Package Manager)

## Steps
Clone the Repository

## Bash

- git clone https://github.com/thendoshane/Steganography-Artifact.git
- cd Steganography-Artifact

## Install Dependencies

- npm install

## Start the Development Server

- npm start
- This will launch the application in your default browser at http://localhost:3000.

Start the Backend (If applicable locally) If the project relies on the local Node server instead of serverless functions:

- node server.js

## Repository Structure
- /src: Contains the React frontend source code (components, logic, styles).
- /api & /functions: Backend logic and serverless function definitions.
- /public: Static assets and entry HTML files.

- server.js: Express server entry point.

## License & Usage
- This software is an academic artifact. It is intended for educational and research purposes as part of the Master's curriculum at the University of Johannesburg.
