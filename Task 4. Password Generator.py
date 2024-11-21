import tkinter as tk
from tkinter import messagebox
import random
import string

# Function to generate password
def generate_password():
    try:
        length = int(password_length_entry.get())
        if length < 8:
            messagebox.showerror("Input Error", "Password length should be at least 8 characters.")
            return

        # Define the character sets
        upper = string.ascii_uppercase
        lower = string.ascii_lowercase
        digits = string.digits
        special_chars = string.punctuation

        # Create a pool of characters based on selected options
        char_pool = ''
        if uppercase_var.get():
            char_pool += upper
        if lowercase_var.get():
            char_pool += lower
        if numbers_var.get():
            char_pool += digits
        if special_var.get():
            char_pool += special_chars

        if not char_pool:
            messagebox.showerror("Input Error", "Please select at least one character type.")
            return

        # Generate the password
        password = ''.join(random.choice(char_pool) for _ in range(length))

        # Display the generated password
        password_output.delete(0, tk.END)
        password_output.insert(0, password)

        # Update password strength
        update_password_strength(password)

        # Save password to history
        add_to_history(password)

    except ValueError:
        messagebox.showerror("Input Error", "Please enter a valid number for password length.")

# Function to update password strength
def update_password_strength(password):
    strength_label.config(text="Password Strength: ", fg="black")
    
    # Strength criteria
    strength_score = 0
    if len(password) >= 12:
        strength_score += 1
    if any(c.isdigit() for c in password):
        strength_score += 1
    if any(c.islower() for c in password):
        strength_score += 1
    if any(c.isupper() for c in password):
        strength_score += 1
    if any(c in string.punctuation for c in password):
        strength_score += 1

    # Update the strength label based on the score
    if strength_score <= 2:
        strength_label.config(text="Password Strength: Weak", fg="red")
    elif strength_score == 3:
        strength_label.config(text="Password Strength: Medium", fg="orange")
    else:
        strength_label.config(text="Password Strength: Strong", fg="green")

# Function to copy password to clipboard
def copy_to_clipboard():
    password = password_output.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

# Function to clear the fields
def clear_fields():
    password_length_entry.delete(0, tk.END)
    password_output.delete(0, tk.END)
    strength_label.config(text="Password Strength: ", fg="black")
    uppercase_var.set(False)
    lowercase_var.set(False)
    numbers_var.set(False)
    special_var.set(False)

# Function to toggle visibility of password
def toggle_visibility():
    if password_visibility_button.config('relief')[-1] == 'sunken':
        password_output.config(show='')  # Show password
        password_visibility_button.config(relief="raised")
    else:
        password_output.config(show='*')  # Hide password
        password_visibility_button.config(relief="sunken")

# Function to save password to file
def save_password():
    password = password_output.get()
    if password:
        with open("generated_passwords.txt", "a") as file:
            file.write(password + '\n')
        messagebox.showinfo("Saved", "Password saved to 'generated_passwords.txt'.")

# Function to add password to history list
def add_to_history(password):
    password_history.insert(tk.END, password)

# Function to clear history
def clear_history():
    password_history.delete(0, tk.END)

# Function to view saved passwords
def view_saved_passwords():
    try:
        with open("generated_passwords.txt", "r") as file:
            saved_passwords = file.readlines()
        
        # Create a new window to display saved passwords
        view_window = tk.Toplevel(root)
        view_window.title("Saved Passwords")
        view_window.geometry("400x300")
        
        # Create a frame to hold the listbox and delete button
        frame = tk.Frame(view_window)
        frame.pack(pady=10)

        # Create a Listbox to display saved passwords
        saved_password_list = tk.Listbox(frame, height=10, width=50)
        saved_password_list.pack(side=tk.LEFT)

        # Insert the saved passwords into the listbox
        for password in saved_passwords:
            saved_password_list.insert(tk.END, password.strip())

        # Function to delete selected password
        def delete_password():
            selected_index = saved_password_list.curselection()
            if selected_index:
                password_to_delete = saved_password_list.get(selected_index)
                saved_password_list.delete(selected_index)

                # Read all saved passwords, remove the selected one, and rewrite the file
                with open("generated_passwords.txt", "r") as file:
                    all_passwords = file.readlines()
                
                with open("generated_passwords.txt", "w") as file:
                    for password in all_passwords:
                        if password.strip() != password_to_delete:
                            file.write(password)
                
                messagebox.showinfo("Deleted", f"Password '{password_to_delete}' deleted successfully.")
            else:
                messagebox.showwarning("Select Password", "Please select a password to delete.")

        # Button to delete selected password
        delete_button = tk.Button(view_window, text="Delete Selected Password", command=delete_password)
        delete_button.pack(pady=10)

    except FileNotFoundError:
        messagebox.showerror("Error", "No saved passwords found.")

# Create the main window
root = tk.Tk()
root.title("Password Generator")
root.geometry("500x600")
root.config(bg="#f0f0f0")

# Create a Canvas widget with Scrollbar
canvas = tk.Canvas(root)
scrollbar = tk.Scrollbar(root, orient="vertical", command=canvas.yview)
canvas.configure(yscrollcommand=scrollbar.set)

# Create a frame to hold the content and link it to the canvas
content_frame = tk.Frame(canvas, bg="#f0f0f0")
canvas.create_window((0, 0), window=content_frame, anchor="nw")

# Place the canvas and scrollbar in the window
canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

# Update the scroll region whenever the content changes
def on_frame_configure(event):
    canvas.configure(scrollregion=canvas.bbox("all"))

content_frame.bind("<Configure>", on_frame_configure)

# Add the rest of your widgets into the content_frame
input_frame = tk.Frame(content_frame, bg="#f0f0f0")
input_frame.pack(pady=20)

output_frame = tk.Frame(content_frame, bg="#f0f0f0")
output_frame.pack(pady=10)

history_frame = tk.Frame(content_frame, bg="#f0f0f0")
history_frame.pack(pady=10)

# Password length entry
tk.Label(input_frame, text="Enter Password Length (min 8):", bg="#f0f0f0", font=("Arial", 10)).pack(pady=5)
password_length_entry = tk.Entry(input_frame, width=30, font=("Arial", 12), relief="solid", borderwidth=2)
password_length_entry.pack(pady=5)

# Character type checkboxes
uppercase_var = tk.BooleanVar()
tk.Checkbutton(input_frame, text="Include Uppercase Letters", variable=uppercase_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor="w", padx=20)
lowercase_var = tk.BooleanVar()
tk.Checkbutton(input_frame, text="Include Lowercase Letters", variable=lowercase_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor="w", padx=20)
numbers_var = tk.BooleanVar()
tk.Checkbutton(input_frame, text="Include Numbers", variable=numbers_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor="w", padx=20)
special_var = tk.BooleanVar()
tk.Checkbutton(input_frame, text="Include Special Characters", variable=special_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor="w", padx=20)

# Buttons for actions
button_style = {'width': 20, 'height': 2, 'bd': 3, 'font': ("Arial", 12, 'bold'), 'bg': '#4CAF50', 'fg': 'white', 'relief': 'flat'}

tk.Button(output_frame, text="Generate Password", command=generate_password, **button_style).pack(pady=10)
tk.Button(output_frame, text="Clear", command=clear_fields, **button_style).pack(pady=5)
tk.Button(output_frame, text="Copy to Clipboard", command=copy_to_clipboard, **button_style).pack(pady=5)
tk.Button(output_frame, text="Save Password", command=save_password, **button_style).pack(pady=5)

# Password output field
password_output = tk.Entry(output_frame, width=40, font=("Arial", 12), relief="solid", borderwidth=2)
password_output.pack(pady=5)

# Button to toggle visibility
password_visibility_button = tk.Button(output_frame, text="Show Password", command=toggle_visibility, **button_style)
password_visibility_button.pack(pady=5)

# Password strength label
strength_label = tk.Label(output_frame, text="Password Strength: ", bg="#f0f0f0", font=("Arial", 10))
strength_label.pack(pady=5)

# Password history
tk.Label(history_frame, text="Password History", bg="#f0f0f0", font=("Arial", 12)).pack(pady=5)
password_history = tk.Listbox(history_frame, width=50, height=6, font=("Arial", 12))
password_history.pack(pady=10)

# Buttons for history actions
tk.Button(history_frame, text="Clear History", command=clear_history, **button_style).pack(pady=5)
tk.Button(history_frame, text="View Saved Passwords", command=view_saved_passwords, **button_style).pack(pady=5)



root.mainloop()