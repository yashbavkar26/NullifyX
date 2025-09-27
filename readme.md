NullifyX – Secure Data Wiping Tool

🔑Generate Private Key:
`openssl genpkey -algorithm RSA -out private.pem -aes256`

🔓 Extract Public Key
`openssl rsa -in private.pem -pubout -out public.pem`

📌 Prerequisites
Before running the tool, make sure you have:
Windows 10/11 with WSL enabled
Install WSL
 and set up Ubuntu (or any Linux distro).
Python 3.11+ installed inside WSL
`python3 --version`


Git installed
`sudo apt update && sudo apt install git -y`

⚙️ Setup Instructions
Open WSL and navigate to the project folder
Example (replace with your username if different):
`cd "/mnt/c/Users/Yash Bavkar/Documents/GitHub/NullifyX"`

Create a virtual environment
`python3 -m venv venv`

Activate the virtual environment
`source venv/bin/activate`


Install required dependencies
`pip install -r requirements.txt`

▶️ Running the Application
Once the environment is ready:
`python gui_app.py`


This will launch the NullifyX GUI inside WSL.
Use it to select a device, choose a wipe method, and generate JSON/PDF certificates of the operation.