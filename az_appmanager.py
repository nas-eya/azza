import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
import sqlite3
import logging
from datetime import datetime
import uuid
from collections import deque
import subprocess
import sys
import bcrypt
import spacy 
import joblib
import sklearn
import requests

print("All imports are successful!")
    #... rest of the code... 
class UserAuthentication:
    def __init__(self):
        self.connection = sqlite3.connect('users.db')
        self.create_user_table()

    def create_user_table(self):
        """Create users table if it doesn't exist."""
        with self.connection:
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    hashed_password TEXT NOT NULL,
                    is_verified BOOLEAN NOT NULL DEFAULT 0,
                    verification_token TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """)

    def register_user(self, username, password):
        """Register a new user with hashed password and a verification token."""
        if self.user_exists(username):
            logging.warning("User already exists.")
            return False
        
        if len(password) < 8:  # Password policy check
            logging.warning("Password must be at least 8 characters long.")
            return False

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        verification_token = str(uuid.uuid4())  # Generate a unique token
        with self.connection:
            self.connection.execute(
                "INSERT INTO users (username, hashed_password, verification_token) VALUES (?, ?, ?)",
                (username, hashed.decode('utf-8'), verification_token)
            )
        self.send_verification_email(username, verification_token)  # Send email with verification link
        logging.info("User registered successfully. Verification email sent.")
        return True

    def authenticate_user(self, username, password):
        """Authenticate user and update last login timestamp."""
        user = self.connection.execute("SELECT hashed_password FROM users WHERE username = ?",
                                       (username,)).fetchone()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[0].encode('utf-8')):
            self.update_last_login(username)
            return True
        return False

    def user_exists(self, username):
        """Check if a user already exists in the database."""
        return self.connection.execute("SELECT 1 FROM users WHERE username = ?",
                                       (username,)).fetchone() is not None

    def send_verification_email(self, username, token):
        """Simulate sending a verification email."""
        verification_link = f"http://yourapp.com/verify?token={token}"
        logging.info(f"Verification email sent to {username}: {verification_link}")

    def verify_user(self, token):
        """Verify user with the provided token."""
        with self.connection:
            user = self.connection.execute(
                "UPDATE users SET is_verified = 1, verification_token = NULL WHERE verification_token = ?",
                (token,)
            ).rowcount
        if user > 0:
            logging.info("User verified successfully.")
            return True
        logging.warning("Verification failed. Invalid token.")
        return False

    def update_last_login(self, username):
        """Update the last login timestamp for the user."""
        with self.connection:
            self.connection.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?",
                (username,)
            )

class Azza:
    def __init__(self, app_manager):
        """Initialize the Azza assistant with the app manager."""
        self.app_manager = app_manager
        self.task_queue = deque()
        self.command_history = []
        self.nlp_model = spacy.load("en_core_web_sm")  # Load a pre-trained NLP model
        self.ml_model = joblib.load('your_model.pkl')  # Load your ML model

    def process_command(self, command):
        """Process user command using NLP and ML."""
        doc = self.nlp_model(command)
        response = self.generate_response(doc)
        self.command_history.append(command)  # Log command history
        return response

    def generate_response(self, doc):
        """Generate a response based on the processed command."""
        # Analyze the command using NLP and ML
        action = self.extract_action(doc)
        if action:
            # Execute corresponding method
            return f"Executing action: {action}"
        return "I didn't understand the command."

    def extract_action(self, doc):
        """Extract the intended action from the processed command."""
        # Here you can implement logic to map NLP output to specific actions
        for token in doc:
            if token.lemma_ == "run":
                return "run_task"
            elif token.lemma_ == "build":
                return "build_app"
        return None

    def browse_web(self, url):
        """Fetch data from the web."""
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.text
            else:
                logging.error(f"Error fetching {url}: {response.status_code}")
                return None
        except Exception as e:
            logging.error(f"Web browsing error: {e}")
            return None

    def create_child_app(self, app_description):
        """Generate code for a child app based on description."""
        code = f"""
# Child App Template
def main():
    print("{app_description}")

if __name__ == "__main__":
    main()
"""
        return code

    def integrate_api(self, api_url):
        """Interact with external APIs."""
        try:
            response = requests.get(api_url)
            if response.status_code == 200:
                return response.json()
            else:
                logging.error(f"API integration error: {response.status_code}")
                return None
        except Exception as e:
            logging.error(f"API integration error: {e}") 
            return None

    def display_command_history(self):
        """Display the history of processed commands."""
        return "\n".join(self.command_history) if self.command_history else "No commands executed yet."

    def cancel_task(self, task):
        """Cancel a queued task."""
        if task in self.task_queue:
            self.task_queue.remove(task)
            logging.info(f"Task '{task}' has been cancelled.")
        else:
            logging.warning(f"Task '{task}' not found in the queue.")

    def show_task_queue_status(self):
        """Show the current status of the task queue."""
        return list(self.task_queue)  # Return a list of tasks in the queue

    def log_task_execution_time(self, task):
        """Log the execution time of a specific task."""
        # Implement logic for timing tasks
        logging.info(f"Logged execution time for task: {task}")

class AppManager:
    def __init__(self):
        """Initialize the AppManager with user authentication and assistant."""
        self.auth = UserAuthentication()
        self.assistant = Azza(self)
        self.is_authorized = False

    def authorize_modification(self):
        """Check if the user is authorized to make modifications.

        Returns:
            bool: True if the user is authorized, False otherwise.
        """
        return self.is_authorized

    def login(self, username, password):
        """Authenticate the user with the given username and password.

        Args:
            username (str): The username of the user.
            password (str): The password of the user.

        Returns:
            bool: True if login is successful, False otherwise.
        """
        if self.auth.authenticate_user(username, password):
            self.is_authorized = True
            logging.info("User logged in successfully.")
            return True
        else:
            logging.error("Invalid credentials.")
            return False
            
    def register(self, username, password):
            """Register a new user with the given username and password.

           Args:
            username (str): The username of the new user.
            password (str): The password for the new user.

        Returns:
            bool: True if registration is successful, False otherwise.
        """
            return self.auth.register_user(username, password)

    def run_task(self, task):
        """Run a specified task if the user is authorized.

        Args:
            task (str): The task to be executed.
        """
        if self.is_authorized:
            try:
                self.assistant.execute_task(task)
                logging.info(f"Executed task: {task}")
            except Exception as e:
                logging.error(f"Failed to run task '{task}': {e}")
        else:
            logging.error("User not authorized to run tasks.")

    def build_app(self, app_description):
        """Generate a new child app based on the given description.

        Args:
            app_description (str): A description of the app to be built.

        Returns:
            str: The generated app code or None if unauthorized.
        """
        if self.is_authorized:
            generated_code = self.assistant.create_child_app(app_description)
            logging.info(f"Generated app code:\n{generated_code}")
            return generated_code
        else:
            logging.error("User not authorized to build apps.")
            return None

    def suggest_improvement(self):
        """Suggest improvements to the code if the user is authorized.

        Returns:
            str: A suggestion for improvement or None if unauthorized.
        """
        if self.is_authorized:
            suggestion = self.assistant.suggest_code_change()
            logging.info(f"Improvement suggestion: {suggestion}")
            return suggestion
        else:
            logging.error("User not authorized to request improvements.")
            return None
        
    def install_library(self, library_name):
        """Install a Python library using pip if the user is authorized.

        Args:
            library_name (str): The name of the library to install.
        """
        if self.is_authorized:
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", library_name], check=True)
                logging.info(f"Successfully installed library: {library_name}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to install library '{library_name}': {e}")
        else:
            logging.error("User not authorized to install libraries.")

    def improve_function(self, func_name):
        """Improve a specified function if the user is authorized.

        Args:
            func_name (str): The name of the function to improve.

        Returns:
            str: The result of the improvement or None if unauthorized.
        """
        if self.is_authorized:
            improvement_result = self.assistant.improve_function(func_name)
            logging.info(f"Improvement result for '{func_name}': {improvement_result}")
            return improvement_result
        else:
            logging.error("User not authorized to improve functions.")
            return None

    def run_queued_tasks(self):
        """Run all tasks in the queue if the user is authorized."""
        if self.is_authorized:
            self.assistant.run_queued_tasks()
            logging.info("All queued tasks have been executed.")
        else:
            logging.error("User not authorized to run queued tasks.")

    def log_action(self, action):
        """Log specific actions taken by the user for auditing.

        Args:
            action (str): The action taken by the user.
        """
        logging.info(f"User action logged: {action}")

class AppGUI:
    def __init__(self, app_manager):
        """Initialize the GUI with the AppManager."""
        self.app_manager = app_manager
        self.root = tk.Tk()
        self.root.title("App Manager")
        self.username_entry = tk.Entry(self.root)
        self.password_entry = tk.Entry(self.root, show='*')
        self.setup_gui()

    def register_user(self):
        """Handle user registration via API."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        self.call_register_api(username, password)

    def call_register_api(self, username, password):
        """Call the backend API to register a user."""
        try:
            response = requests.post("http://backend-url/register", json={"username": username, "password": password})
            if response.status_code == 200:
                messagebox.showinfo("Success", "Registration successful!")
            else:
                messagebox.showerror("Error", "Registration failed: " + response.text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def login_user(self):
        """Handle user login via API."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        self.call_login_api(username, password)

    def call_login_api(self, username, password):
        """Call the backend API to log in a user."""
        try:
            response = requests.post("http://backend-url/login", json={"username": username, "password": password})
            if response.status_code == 200:
                messagebox.showinfo("Success", "Login successful!")
                self.root.destroy()
                self.open_dashboard()
            else:
                messagebox.showerror("Error", "Invalid credentials.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def install_library(self):
        """Install a library based on user input via API."""
        library_name = simpledialog.askstring("Library Name", "Enter the name of the library to install:")
        if library_name:
            self.call_install_library_api(library_name)

    def call_install_library_api(self, library_name):
        """Call the backend API to install a library."""
        try:
            response = requests.post("http://backend-url/install", json={"library_name": library_name})
            if response.status_code == 200:
                messagebox.showinfo("Success", f"Library '{library_name}' installed successfully!")
            else:
                messagebox.showerror("Error", f"Failed to install library: {response.text}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def run_task(self):
        """Run a specified task via API."""
        task = simpledialog.askstring("Task", "Enter the command to run:")
        if task:
            self.call_run_task_api(task)

    def call_run_task_api(self, task):
        """Call the backend API to run a task."""
        try:
            response = requests.post("http://backend-url/run_task", json={"task": task})
            if response.status_code == 200:
               self.result_area.insert(tk.END, f"Task executed: {task}\n")
            else:
                messagebox.showerror("Error", "Failed to execute task: " + response.text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def build_app(self):
        """Build a new app based on user input via API."""
        app_description = simpledialog.askstring("App Description", "Enter a brief description of the app:")
        if app_description:
            self.call_build_app_api(app_description)

    def call_build_app_api(self, app_description):
        """Call the backend API to build an app."""
        try:
            response = requests.post("http://backend-url/build", json={"description": app_description})
            if response.status_code == 200:
                code = response.json().get('code', '')
                self.result_area.insert(tk.END, f"Generated app code:\n{code}\n")
            else:
                messagebox.showerror("Error", "Failed to build app: " + response.text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def suggest_improvement(self):
        """Suggest code improvements via API."""
        self.call_suggest_improvement_api()

    def call_suggest_improvement_api(self):
        """Call the backend API to suggest improvements."""
        try:
            response = requests.get("http://backend-url/suggest_improvement")
            if response.status_code == 200:
                suggestion = response.json().get('suggestion', '')
                if suggestion:
                    messagebox.showinfo("Suggestion", suggestion)
                    self.result_area.insert(tk.END, f"Improvement suggested: {suggestion}\n")
            else:
                messagebox.showerror("Error", "Failed to get suggestion: " + response.text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def improve_function(self):
        """Improve a specified function via API."""
        func_name = simpledialog.askstring("Function Name", "Enter the name of the function to improve:")
        if func_name:
            self.call_improve_function_api(func_name)

    def call_improve_function_api(self, func_name):
        """Call the backend API to improve a function."""
        try:
            response = requests.post("http://backend-url/improve_function", json={"function_name": func_name})
            if response.status_code == 200:
                result = response.json().get('result', '')
                self.result_area.insert(tk.END, f"Improvement result for '{func_name}': {result}\n")
            else:
                messagebox.showerror("Error", "Failed to improve function: " + response.text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def view_command_history(self):
        """View the history of commands executed via API."""
        self.call_view_command_history_api()

    def call_view_command_history_api(self):
        """Call the backend API to get command history."""
        try:
            response = requests.get("http://backend-url/command_history")
            if response.status_code == 200:
                history = response.json().get('history', [])
                if history:
                    self.result_area.insert(tk.END, "Command History:\n" + "\n".join(history) + "\n")
                else:
                    messagebox.showinfo("Command History", "No commands executed yet.")
            else:
                messagebox.showerror("Error", "Failed to retrieve command history: " + response.text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def cancel_task(self):
        """Cancel a specified task via API."""
        task = simpledialog.askstring("Cancel Task", "Enter the name of the task to cancel:")
        if task:
            self.call_cancel_task_api(task)

    def call_cancel_task_api(self, task):
        """Call the backend API to cancel a task."""
        try:
            response = requests.post("http://backend-url/cancel_task", json={"task": task})
            if response.status_code == 200:
                self.result_area.insert(tk.END, f"Requested cancellation of task: {task}\n")
            else:
                messagebox.showerror("Error", "Failed to cancel task: " + response.text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def show_task_queue_status(self):
        """Show the current status of the task queue via API."""
        self.call_show_task_queue_status_api()

    def call_show_task_queue_status_api(self):
        """Call the backend API to get the task queue status."""
        try:
            response = requests.get("http://backend-url/task_queue_status")
            if response.status_code == 200:
                status = response.json().get('status', '')
                messagebox.showinfo("Task Queue Status", f"Current tasks in queue: {status}")
            else:
                messagebox.showerror("Error", "Failed to retrieve task queue status: " + response.text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def log_execution_time(self):
        """Log execution time for a specified task via API."""
        task = simpledialog.askstring("Task Execution Time", "Enter the task to log execution time:")
        if task:
            self.call_log_execution_time_api(task)

    def call_log_execution_time_api(self, task):
        """Call the backend API to log execution time."""
        try:
            response = requests.post("http://backend-url/log_execution_time", json={"task": task})
            if response.status_code == 200:
                self.result_area.insert(tk.END, f"Logged execution time for task: {task}\n")
            else:
                messagebox.showerror("Error", "Failed to log execution time: " + response.text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def process_command(self):
        """Process a user command via API."""
        command = simpledialog.askstring("Command", "Enter the command to process:")
        if command:
            self.call_process_command_api(command)

    def call_process_command_api(self, command):
        """Call the backend API to process a command."""
        try:
            response = requests.post("http://backend-url/process_command", json={"command": command})
            if response.status_code == 200:
                result = response.json().get('result', '')
                self.result_area.insert(tk.END, f"Processed command: {result}\n")
            else:
                messagebox.showerror("Error", "Failed to process command: " + response.text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def browse_web(self):
        """Browse a specified URL via API."""
        url = simpledialog.askstring("URL", "Enter the URL to browse:")
        if url:
            self.call_browse_web_api(url)

    def call_browse_web_api(self, url):
        """Call the backend API to browse a web URL."""
        try:
            response = requests.get(f"http://backend-url/browse?url={url}")
            if response.status_code == 200:
                content = response.text
                self.result_area.insert(tk.END, f"Web Content from {url}:\n{content}\n")
            else:
                messagebox.showerror("Error", "Failed to fetch content: " + response.text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def create_child_app(self):
        """Create a child app based on user input via API."""
        app_description = simpledialog.askstring("App Description", "Enter a brief description of the child app:")
        if app_description:
            self.call_create_child_app_api(app_description)

    def call_create_child_app_api(self, app_description):
        """Call the backend API to create a child app."""
        try:
            response = requests.post("http://backend-url/create_child_app", json={"description": app_description})
            if response.status_code == 200:
                code = response.json().get('code', '')
                self.result_area.insert(tk.END, f"Child App Code:\n{code}\n")
            else:
                messagebox.showerror("Error", "Failed to create child app: " + response.text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def integrate_api(self):
        """Integrate with an API based on user input via API."""
        api_url = simpledialog.askstring("API URL", "Enter the API URL to integrate:")
        if api_url:
            self.call_integrate_api(api_url)

    def call_integrate_api(self, api_url):
        """Call the backend API to integrate with another API."""
        try:
            response = requests.post("http://backend-url/integrate_api", json={"api_url": api_url})
            if response.status_code == 200:
                api_response = response.json().get('response', '')
                self.result_area.insert(tk.END, f"API Response: {api_response}\n")
            else:
                messagebox.showerror("Error", "Failed to integrate API: " + response.text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")



    # Add similar API call methods for other functionalities...
    # For example: improve_function, view_command_history, run_task, etc.
