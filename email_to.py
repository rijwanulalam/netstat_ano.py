# print("""Hello, World!
# Hudai""")

# name = "rijwanul"
# age = 30

# print("My name is " +name+ " and I am " +str(age)+ " years old.")

# age += 1
# print(age)

# day = 1
# age += day
# print(age)

# def greet(name="Rehan"):
#     print("Hello, " + name)

# greet("Rijwanul")
# greet()

# for i in range(3):
#     print(i)

# my_tupple = (1, 2, 3)
# my_tupple = my_tupple + (4, 5, 6)
# print(my_tupple)

# person = {'name': 'Alice', 'age': 25}
# print(person['age'])


# Source - https://stackoverflow.com/a/40412059
# Posted by r0xette
# Retrieved 2026-09-19, License - CC BY-SA 3.0

#!/usr/bin/python3

# Import smtplib for the actual sending function
# import smtplib

# Import the email modules we'll need
# from email.message import EmailMessage

# # # Open the plain text file whose name is in textfile for reading.
# # with open(textfile) as fp:
# #     # Create a text/plain message
# #     msg = EmailMessage()
# #     msg.set_content(fp.read())

# # me == the sender's email address
# # you == the recipient's email address
# msg['Subject'] = 'Hello World!'
# msg['From'] = 'rijwanul007@gmail.com'
# msg['To'] = 'hridoy99723@gmail.com'

# # Send the message via our own SMTP server.
# s = smtplib.SMTP('localhost')
# s.send_message(msg)
# s.quit()
   
import smtplib
import ssl
from email.message import EmailMessage
import os

# Configuration
sender_email = "rijwanul007@gmail.com"
password = "vmvj iswr jbyc iqwf"
smtp_server = "smtp.gmail.com"
smtp_port = 587  # For starttls

# Create message
msg = EmailMessage()
msg["Subject"] = "Test Email"
msg["From"] = "rijwanul007@gmail.com"
msg["To"] = "mashihoor@gmail.com"
msg.set_content("test= “This is a super text”")

# Send email
context = ssl.create_default_context()
with smtplib.SMTP(smtp_server, smtp_port) as server:
    server.starttls(context=context)
    server.login("rijwanul007@gmail.com", "vmvj iswr jbyc iqwf")
    server.send_message(msg)   