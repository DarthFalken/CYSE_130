# CYSE_130

LOGGER_130

Logger 130 is a automated security system with the ability to analyze logs, network traffic, moniter system use, and send alerts for anything going on.


HOW TO USE LOGGER_130

download the python script.

open in VS code or platform of your choice.

install any of the python libraries that you do not currently have.

run the script.



LOGGER_130 INSTRUCTIONS AND USE CASES


analyze_log Function Documentation
Overview
The analyze_log function analyzes a vsftpd log file, either the default one in the same directory
as the script or a user-specified log file. It extracts various statistics such as the number of
successful and failed logins, bytes uploaded and downloaded, directories created and deleted,
and more. The results are printed to the console.

Function Definition
def analyze_log(filename: str=None):
send_alert Function Documentation
Overview
The send_alert function is responsible for sending alert emails with a specified subject and
body. It creates an email message, configures the necessary headers, and sends the email
using the SendGrid SMTP server over a secure connection.

Function Definition
def send_alert(subject, body):
__convBytes Function Documentation
Overview
The __convBytes function converts a given number of bytes into a more human-readable
format, breaking it down into petabytes, terabytes, gigabytes, megabytes, kilobytes, and bytes.
It can also format the output as a string with the largest applicable unit.

Function Definition
def __convBytes(bs: int, format: bool=False):
analyze_system Function Documentation
Overview
The analyze_system function monitors and logs various system statistics, including CPU usage,
memory usage, storage usage, and network activity. It can print results to the terminal, save
logs to a file, and send alert emails when certain thresholds are exceeded.

Function Definition
def analyze_system(CPU: bool=True, MEM: bool=True, STO: bool=True, NET: bool=True,
intface: str="Wi-Fi", save: bool=False, pri: bool=True, interval: int=1, disk: str='/', emails:
bool=True):
settings

Function Documentation
Overview
The settings function provides a user interface for modifying the default settings of the system
monitoring tool. The settings that can be changed include the default network interface, the
default disk for measuring usage, and the default email address for sending logs.


Function Definition
def settings():
packet_callback Function Documentation
Overview
The packet_callback function is used with Scapy to process each packet received by the
network interface card (NIC). This function extracts relevant information from the packets,
creates a log entry, and prints the details.
Function Definition
def packet_callback(packet):
loopNmap Function Documentation
Overview
The loopNmap function continuously runs the nmap command with specified arguments and
delays between each execution. This loop will continue indefinitely until a termination condition
is met.

Function Definition
def loopNmap(args: str, delay: int, save, name):
nmap Function Documentation
Overview
The nmap function executes the nmap network scanning tool with specified arguments. It can
prompt the user for input if no arguments are provided, and it can save the output to a file if
specified.

Function Definition
def nmap(args: str=None, save: bool=False, name: str=None):
security_check Function Documentation
Overview
The security_check function provides a menu-driven interface for the user to perform various
security-related tasks, such as running an Nmap scan, analyzing network traffic, or starting and
stopping automated scanning.
Function Definition
def security_check():

__c Function Documentation
Overview
The __c function is a custom utility designed to clear the terminal output, providing a clean
workspace for the user. It adapts to the operating system being used and executes the
appropriate command to clear the terminal screen.
Function Definition
def __c():

main Function Documentation
Overview

The main function serves as the entry point for the application, providing a menu-driven
interface that allows users to select various options for system analysis and management. It can
also be called with an argument to bypass the input check.
Function Definition
def main(choice: int = 0):
This part of the documentation was written with ChatGPT, and some human input. View the conversation here
https://chatgpt.com/share/67241a02-4f8c-800b-b42d-d4e673e3d13d
