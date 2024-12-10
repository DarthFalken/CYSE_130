try:
    import os
    from datetime import datetime as dt
    import psutil as ps
    import time
    from math import *
    import smtplib
    from email.message import EmailMessage
    from scapy.all import *
    from scapy.utils import *
    import subprocess
    import threading
except ModuleNotFoundError as e:
    print("You need to install " + e.msg.split('\'')[1])
    print("pip install " + e.msg.split('\'')[1] )
    exit()


#Code so hex(2989) they know cheatgpt aint wrote it!
#Uploaded exactly 4.2 openAI API secrets while writing this 
#Coding in 4:3 like a global 31337 makes the BP's easier to hit ;) (16:10 == 🗑️)
#Any issues created containing any mention of comments or documentation will be autoclosed and marked "Skill Issue"
# ): <- Python "Programmers" when there isn't a module and subsequent SO article for whatever they are doing (I cant really be talking, convBytes is a blatant violation of the geneva convention)

class __Logger:                         #This is a class used to store global variables. 
    DISK = "/"                          #Default disk used
    INTERFACE = "Wi-Fi"                 #Defualt network adapter used.
    EMAIL = 'dcharnic@gmu.edu'          #Email to send the alerts to
    SENDEMAILS = True                   #Whether or not to send email alerts
    CPUTHRESHOLD = 75                   #Maximum allowed cpu percentage before an email alert is sent
    CPUTIMEOUT = 5                      #Amount of time in between emails
    CPUTIMEREC = 0                      #CPU TRACKING NUMBER
    MEMTHRESHOLD = 20                   #Maximum GB of memory left before an email is sent. 
    MEMTIMEOUT = 15                     #Amount of time in between emails
    MEMTIMEREC = 0                      #MEMORY TRACKING NUMBER
    DISKTHRESHOLD = 100                 #The number in GB used to dertimine how much disk space should be left before sending an alert. In this case an alert is sent if the disk goes lower than 100GB
    DISKTIMEOUT = 60                    #Amount of time in between emails
    DISKTIMEREC = 0                     #DISK TRACKING NUMBER
    LOGSAVEFILE = "Default.log"         #The log file that logs are saved to
    LOGENTRIESBEFORESAVE = 25           #Number of log entries to keep in memory before writing them, used to save disk writes when run for a long time
    NMAPLOOP = False
class __rgb:                            #Defines a set of ANSI escape codes to allow for simple terminal color changing. A list of these can be found on https://en.wikipedia.org/wiki/ANSI_escape_code
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BLINK = '\033[6m'
    E = '\033[0m'                       #This is the standard terminal print color, tells the terminal to go back to "normal"

def send_alert(subject, body):          #The function used to fire off the emails. 
    msg = EmailMessage()                #Creates a new email object
    msg.set_content(body)               #Sets the body of the email to the body the user passed in
    msg['Subject'] = subject            #Sets the subject of the email to whatever the user passed in
    msg['From'] = 'cyse8389@gmail.com'  #The email address we are sending these emails from 
    msg['To'] = __Logger.EMAIL          #The email address we are sending these to, configurable via settings or by changing the default value in __Logger.EMAIL

    with smtplib.SMTP_SSL('smtp.sendgrid.net', 465) as smtp:                                            #Start a new SMTP connection
        smtp.login('apikey', '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')   #Login to the SMTP server
        try:                                                                                            #Tries to send the email
            smtp.send_message(msg)                                                                      #Sends the email
        except Exception as e:                                                                          #If something breaks or isn't working this will catch it
            print(e)                                                                                    #Prints the error if there is one

def __convBytes(bs: int, format: bool=False):
    #All of this is a warcrime to the language and its creators and I dont want to talk about it
    pb, tb, gb, mb, kb, b = 0, 0, 0, 0, 0, 0
    pb = floor(bs / pow(1000, 5))
    bs -= pb * pow(1000, 5)
    tb = floor(bs / pow(1000, 4))
    bs -= tb * pow(1000, 4)
    gb = floor(bs / pow(1000, 3))
    bs -= gb * pow(1000 , 3)
    mb = floor(bs / pow(1000, 2))
    bs -= mb * pow(1000 , 2)
    kb = floor(bs / 1000)
    bs -= kb * 1000
    b = bs
    arr = [pb, tb, gb, mb, kb, b]
    if format:
        sts = 0
        finc = ["PB", "TB", "GB", "MB", "KB", "B"]
        while sts < 5:
            if(arr[sts] !=0):
                arr ="{:02d}".format(arr[sts]) + " " + finc[sts]
                break
            sts+=1
        return arr
    else:
        return arr

def analyze_log(filename: str=None):                                                                                #Defines analyze_log
    __c()                                                                                                           #Clears the terminal
    print("Would you like to use the default log or your own vsftpd log?")                                          #Print statement
    print("Default log needs to be in the same directory as the script.")                                           #Print statement
    print("Use default: yes or no ")                                                                                #Print statement
    if input("> ").lower().find("y") != -1:                                                                         #Checks if the user wants to use the default log
        filename = os.getcwd() + "\\" + "vsftpd.log"                                                                #Retrieves the current working directory appends the default log name to it (vsftpd.log) and stores the filename in filename
        with open(filename, 'r') as f:                                                                              #Opens the file in filename
            lines = f.readlines()                                                                                   #Reads all of the lines in the file into an array called lines
    else:
        while True:                                                                                                 #Creates a loop so if the user types something wrong, they can try again
            if filename == None:                                                                                    #Checks if filename doesn't exist
                print("Please enter the full path of the file you would like to analyze ")                          #Print statement
                print("If the file is in the same directory, please just provide the file name.")                   #Print statement
                filename = input("> ")                                                                              #Prompts the user for the file path
                if filename.find("\\") == -1:                                                                       #Checks if the user provided a full path or just a file
                    filename = os.getcwd()+ '\\' + filename                                                         #If the user provides the file name, it retrieves the full path for the file. 
            try:
                with open(filename, 'r') as f:                                                                      #Opens the file provided
                    lines = f.readlines()                                                                           #Reads the lines of the file provided into the array
                    break                                                                                           #If everything works, this will break the loop and the program will continue
            except FileNotFoundError:                                                                               #If the file name the user provided was invalid this will hit. 
                    __c()                                                                                           #Clears the terminal
                    print("That file doesn't exist")                                                                #Print statement
                    filename = None                                                                                 #Sets filename to none so it will be caught by the same loop
                    
    num_of_good_logins = 0                                                                                          #These are all of the statistics for our file. They are set to 0 by default
    num_of_bad_logins = 0
    bytes_uploaded = 0
    dirs_created = 0
    bytes_downloaded = 0
    clients_who_connected = []
    clients_who_couldnt_connect = []
    files_deleted = 0
    dirs_deleted = 0
    files_downloaded = 0
    files_uploaded = 0
    num_of_connections = 0
    for x in lines:                                                                                                 #Loop through each line in the log
        if x.find('OK LOGIN') != -1:                                                                                #The variable names are fairly intuitive so you should be able to understand what this section does
            num_of_good_logins +=1                                                                                  #If you are trying to understand the string splicing and indexing it may help to have the log file open in another tab
            client = x.split("\"")[-2]
            if client not in clients_who_connected:                                                                
                clients_who_connected.append(client)

        if x.find("FAIL LOGIN") != -1:                                                                  
            num_of_bad_logins +=1
            client = x.split("\"")[-2]
            if client not in clients_who_couldnt_connect:
                clients_who_couldnt_connect.append(client)

        if x.find("CONNECT") != -1:
            num_of_connections+=1
        
        if x.find("OK MKDIR")!= -1:
            dirs_created +=1

        if x.find("OK RMDIR") != -1:
            dirs_deleted +=1

        if x.find("OK DELETE"):
            files_deleted+=1
        
        if x.find("OK UPLOAD") != -1:
            split = x.split(",")
            num = split[-2].split(' bytes')[0]
            bytes_uploaded += int(num)
            files_uploaded +=1

        if x.find("OK DOWNLOAD") != -1:
            split = x.split(",")
            num = split[-2].split(' bytes')[0]
            bytes_downloaded += int(num)
            files_downloaded +=1
    
    bytes_downloaded = __convBytes(bytes_downloaded, True)                                                          #Coverts a large number of bytes (say 1,000,000) to its largest sensical data value (1GB), and appends the correct suffix 
    bytes_uploaded = __convBytes(bytes_uploaded, True)
    
    __c()
    print(f"Stats for: {filename}")
    print(f"Number of connections:                  {__rgb.BLINK}{num_of_connections} {__rgb.E}")
    print(f"Clients who couldn't connect:           {__rgb.FAIL}{clients_who_couldnt_connect} {__rgb.E}")
    print(f"Clients who could connect:              {__rgb.OKGREEN}{clients_who_connected}{__rgb.E}")
    print(f"Number of successful logins:            {__rgb.OKGREEN}{num_of_good_logins}{__rgb.E}")
    print(f"Number of failed logins:                {__rgb.FAIL}{num_of_bad_logins}{__rgb.E}")
    print(f"Number of bytes uploaded:               {__rgb.OKBLUE}{bytes_uploaded}{__rgb.E}")
    print(f"Number of bytes downloaded:             {__rgb.OKBLUE}{bytes_downloaded}{__rgb.E}")
    print(f"Number of files uploaded:               {__rgb.OKBLUE}{files_uploaded}{__rgb.E}")
    print(f"Number of files downloaded:             {__rgb.OKBLUE}{files_downloaded}{__rgb.E}")    
    print(f"Number of directories created           {__rgb.OKCYAN}{dirs_created}{__rgb.E}")
    print(f"Number of directories deleted           {__rgb.WARNING}{dirs_deleted}{__rgb.E}")
    print(f"Number of entries in logfile:           {__rgb.OKCYAN}{len(lines)}{__rgb.E}")
    print(f"Press enter to return to main menu")
    if input(">") != None:                                                                                         #Press any key to return to the menu
        __c()
        main()

def analyze_system(CPU: bool= True, MEM: bool=True, STO: bool=True, NET: bool=True, intface: str="Wi-Fi",save: bool=False, pri: bool=True, interval: int=1, disk: str='/', emails: bool=True):                   #Defines analyze_system
    __c()                                                                                                                                                                                   #Clears the screen
    while True:                                                                                                                                                                             #Loop to check the users input
        try:                                                                                                                                                                                
            _ = ps.net_io_counters(pernic=True)[intface]                                                                                                                                    #attempts to read the network counters from the interface provided, if its invalid, it will throw an exception, and the loop will prompt you for a new interface
            break                                                                                                                                                                           #If the user provided a valid input, break out of the loop
        except KeyError:
            print("The interface you provided is invalid, please enter the correct one")
            print(f"Your valid options are: {ps.net_io_counters(pernic=True).keys()}")                                                                                                      #Show the user what interfaces they have
            intface = input("> ")    
    print("Print results to terminal: yes or no")                                                                                                                                           #Asks the user if they want to print the logs to the terminal
    if input("> ").lower().find("y") != -1:                                                                                                                                                 #If the user's input contains a 'y' then the user wants to print the logs
        pri = True
    print("Save results to a file? ")                                                                                                                                                       #Asks the user if they want to save their logs
    if input("> ").lower().find("y") != -1:                                                                                                                                                 #If the user's input contains a 'y' then the user wants to save the logs
        save = True
    __c()
    try:
        while True:
            time.sleep(interval)                                                                                                                                                            #Sleep for interval seconds
            cpu = ''                                                                                                                                                                        #These are strings that will be used later, setting them to empty strings allows for ease of use
            mem = ''
            sto = ''
            net = ''
            alert = ''
            logsave = ""
            if(CPU):                                                                                                                                                                        #If the user wants to use the CPU info in their logs, do the following
                cpu = f" CPU: {(str(round((ps.cpu_percent() * 100 / ps.cpu_count()), 3)).rjust(5)) } %"                                                                                     #Just prints out the percentage of the cpu thats being used, does it to a string length of 5 (15) becomes (   15)
                cach = round((ps.cpu_percent() * 100 / ps.cpu_count()), 3)                                                                                                                  #Uses the same CPU percentage query for everything, it is possible that the CPU breifly spikes above the threshold, and then comes down, which could break the send alert function
                if(cach > __Logger.CPUTHRESHOLD):                                                                                                                                           #Checks if the CPU is above the set threshold
                    if(dt.now().minute % __Logger.CPUTIMEOUT == 0 and __Logger.CPUTIMEREC != dt.now().minute):                                                                              #This is complicated but they all use the same logic / method so I'm  going to explain it here
                        send_alert("High CPU usage on server", f"The server just hit {str(round((ps.cpu_percent() * 100 / ps.cpu_count()), 3))}% cpu usage")                                #This section basically says that if the cpu hit the threshold, and its been __Logger.CPUTIMEOUT minutes since the last alert, send another email. This is done to prevent us from spamming the email
                        __Logger.CPUTIMEREC = dt.now().minute                                                                                                                               #__Logger.CPUTIMEREC is an easy way for us to track the last time an email was sent, you do not modify this number
                    alert += f"\nHIGH CPU USAGE {cach}%"                                                                                                                                    #An alert is added to the log file regardless of how long its been since the last email.
            if(MEM):                                                                                                                                                                        #If the user wants to use the memory util, add memory info to the logs
                mem = f" MEM: {__convBytes(ps.virtual_memory().used, True)} used of {__convBytes(ps.virtual_memory().total, True)} availible"                                               #Same logic as the CPU
                if(__convBytes(ps.virtual_memory().used)[2] == 0 or __convBytes(ps.virtual_memory().used)[2] < __Logger.MEMTHRESHOLD):                                                      #__convBytes is used to convert the memory used in bytes into gigabytes / mb. 32 gb of memory is ~34003574784 bytes of mem (I cant figure out where the extra 2gb is coming from, swap maybe?)
                    if(dt.now().minute % __Logger.MEMTIMEOUT == 0):                                                                                                                         #__convBytes if True is not passed through the format argument to convBytes, it will return an array of 5 integers, [terabytes, gigabytes, megabytes, kilobytes, bytes]
                        if(emails and __Logger.MEMTIMEREC != dt.now().minute):                                                                                                              #Same alert logic as CPU
                            send_alert("Memory is low", f"System only has {__convBytes(ps.virtual_memory().free, True)} REMAINING")
                        alert+=f'\n {__convBytes(ps.virtual_memory().free, True)} REMAINING'
                        __Logger.MEMTIMEREC = dt.now().minute
            if(STO):                                                                                                                                                                        #Nearly exactly the same as MEM, I was a little tired so it looks different but it does the same exact thing as the memory one
                try:
                    sto = f" STO: {__convBytes(ps.disk_usage(path=disk).used, True)} used of {__convBytes(ps.disk_usage(path=disk).total, True)} availible"
                    if(__convBytes(ps.disk_usage(path=disk).free)[0:2] == [0, 0] and __convBytes(ps.disk_usage(path=disk).free)[2] < 100):
                        if(dt.now().minute % __Logger.DISKTIMEOUT == 0 and __Logger.DISKTIMEREC == 0 and emails):
                            send_alert("DISK IS FULL", f"Drive: {disk} is full and only has {__convBytes(ps.disk_usage(path=disk).free)[2]} GB remaining")
                        if(dt.now().minute % __Logger.DISKTIMEOUT == 0 and dt.now().minute != __Logger.DISKTIMEREC):
                            alert+=f'\nLOW STORAGE ON {disk} {__convBytes(ps.disk_usage(path=disk).free, True)} LEFT'                                                                       #This one does not save the alert to the log file every time it is hit, that would flood your log file.
                            __Logger.DISKTIMEREC = dt.now().minute
                except OSError:                                                                                                                                                             #This is raised if psutil cannot find the disk you specified
                    print("Please specify the correct disk to check: " + disk + "is not valid")                                                                                             #Prints the error message with the disk you used
            if(NET):                                                                                                                                                                        #Logs the network statistics, not really a great way to measure network traffic through psutil so no alerts are generated by this
                net = f" NET: {ps.net_io_counters(pernic=True)[intface].packets_sent} packets sent and {ps.net_io_counters(pernic=True)[intface].packets_recv} packets received "           #Constructs the network statistics from the interface you provided
            counter = 0
            log = f"[{dt.now()}]" + cpu + mem + sto + net + alert + '\n'                                                                                                                    #Constructs the final log
            logsave += log                                                                                                                                                                  #Adds this entry to logsave
            if pri:                                                                                                                                                                         #Prints the logs if you said yes to printing
                print(log.split('\n')[0])
                print("Press CTRL - C to return to the menu", end='\r')                                                                                                                     #Prints the message with a carriage return at the end, instead of a newline. This means that the next thing to get printed will actually get printed on top of this.
            if save:
                if(counter % __Logger.LOGENTRIESBEFORESAVE == 0):                                                                                                                           #__Logger.LOGENTRIESBEFORESAVE specifies the number of log entries to save in logsave before they are written, saves disk cycles
                    with open(__Logger.LOGSAVEFILE, 'a') as f:                                                                                                                              #Appends to the file in __logger.LOGSAVEFILE
                        f.write(logsave)
                        logsave = ''
                counter+=1
    except KeyboardInterrupt:                                                                                                                                                               #If the user presses ctrl-c the program returns to main
        main()    

def settings():                                                                         #Defines settings
    __c()                                                                               #List of options in settings
    options = {1: 'Change interface used by default',
               2: 'Change default disk used',
               3: 'Change default email used'}
    print("Your options are: ")
    for x in options.keys():                                                            #Prints each option with a corresponding key
        print(str(x) + f": {options[x]}")
    print("Please choose an option: ")
    opt = ''
    while True:
        try:
            opt = int(input("> "))                                                      #Ensures the user chose a correct option. If they did then they option is saved in opt, and the loop breaks. 
            opst = options[opt]
            break
        except:
            print("Invalid option, try again")
    match opt:                                                                          #Matches the option the user chose to the corresponding code. 
        case 1:
            while True:                                                                 #Logic for setting the interface. 
                __c()
                print("You may set your interface to one of the following")
                lis = []
                for x in ps.net_io_counters(pernic=True):
                    lis.append(x)
                for x in range(0, len(lis)):
                    print(str(x) +  ": " + lis[x])                                      #Prints out your interfaces with a corresponding key
                try:
                    chose = input("Choice> ")                                           #Places your input into chose, and if you provided a valid key, breaks the loop, otherwise prompts you again
                    dev = lis[int(chose)]
                    break
                except KeyError:
                    print("Not in the range provided")
                    time.sleep(2)
                except:
                    print(f"Bad option, please enter a number 0-{len(lis)-1}")
                    time.sleep(2)
            __Logger.INTERFACE = dev
            print(f"Default interface was successfully changed to {__Logger.INTERFACE}")
            time.sleep(2)
            main()                                                                      #Returns to main
        case 2:
            __c()
            while True:                                                                 #Logic for changing the disk used
                print("Change the default disk / folder used to measure disk usage")
                print(f"Currently set to {__Logger.DISK}")
                try:
                    print("Please type the folder or drive you would like to set as the default. Examples look like `C:\\` for windows or `/` on linux")
                    i = input("> ")
                    if(i == "_exit"):                                                   #Prompts the user for the drive they want to use then exits
                        break
                    assert os.path.isdir(i)                                             #Makes sure its a valid directory
                    __Logger.DISK = i
                    print(f"Successfully set disk to {__Logger.DISK}")                  #Does anyone read these or am I wasting my time 🥲
                    time.sleep(2)
                    break
                except:
                    print("Folder not found, try again, \"_exit\" to cancel")
            main()
        case 3:
            __c()
            while True:                                                                 #I mean this is basically the same as the other ones, its very self explanatory, you can understand. 
                try:
                    print(f"Change the default email address to send logs to, it's currently set to {__Logger.EMAIL}\nUse `_exit` to cancel")
                    inp = input(">")
                    if inp == "_exit":
                        break
                    else:
                        __Logger.EMAIL = inp
                        print("Successfully changed email")
                        break
                except:
                    print("Something went wrong")
            main()

def packet_callback(packet):                                            #This function is used with scapy to proccess each packet that your nic recieves. 
    timestamp = dt.now().strftime("%Y-%m-%d %H:%M:%S")                  #Creates a timestamp
    if packet.haslayer(IP):                                             #Checks if the packet is an ip packet
        ip_src = packet[IP].src                                         #sets ip_src and ip_dst to the appropriate values
        ip_dst = packet[IP].dst
        protocol = "OTHER"                                              #Sets the protocol to OTHER. If the packet is not OTHER, it should get changed accordingly later
        if packet.haslayer(TCP):                                        #Checks if the packet is a tcp packet
            protocol = "TCP"                                            #sets ip_src and ip_dst to the appropriate values
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):                                      #Checks if the packet is a udp packet
            protocol = "UDP"                                            #sets ip_src and ip_dst to the appropriate values
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):                                     #Checks if the packet is an ICMP packet
            protocol = "ICMP"
            src_port = dst_port = "N/A"  
        log = f"[{timestamp}] {ip_src}:{src_port} -> {ip_dst}:{dst_port} | Protocol: {protocol} | Length: {len(packet)} bytes"
        print(f"[{timestamp}] {ip_src}:{src_port} -> {ip_dst}:{dst_port} | Protocol: {protocol} | Length: {len(packet)} bytes")
    else:
        print(f"[{timestamp}] Non-IP packet detected")

def loopNmap(args: str, delay: int, save, name):
    __Logger.NMAPLOOP = True                                            #Sets the global NMAPLOOP True, used for the green box on the menu
    while True:                                                             
        nmap(args, save, name)                                          #Runs nmap with the arguments provided
        time.sleep(delay)                                               #Waits for delay seconds

def nmap(args: str=None, save: bool=False, name: str=None ):
    if args is None:                                                                                        #Checks if the arguments variable exists, if not we need to prompt the user for their argument
        print("Please enter your target host, press enter to use localhost")
        hostname = input("> ")
        if len(hostname.strip()) == 0:                                                                      #Use localhost if you're lazy
            hostname = "localhost"
        print("Enter your arguments, per line, an example argument looks like \"-sV\" or \"-p 3389-4999\"")
        print("Press enter to finish your arguments")
        args = ["nmap"]
        args.append(hostname)
        while True:                                                                                         #Lets the user input as many arguments for nmap as they want, when they are done, they press enter. 
            inp = input("> ")
            if len(inp.strip()) != 0:
                args.append(inp)
            else:
                break    
    arr = []
    proc = subprocess.Popen(args,stdout=subprocess.PIPE)                                                    #Runs the command and pipes the output to subprocess.PIPE so we can read from it later
    while True:
        line = proc.stdout.readline()                                                                       #Reads each line of output from nmap until there are none left. 
        if not line:
            break
        arr.append(line.rstrip().decode("utf-8") + "\n")                                                    #Formats / converts the lines so they look normal. 
    if save:
        with open(name, 'a') as f:
            f.writelines(arr)                                                                               #Writes each line to the file we specified, if we asked nmap to save it. 
    return arr

def security_check():
    __c()                                                                                                               #Bro who wrote this
    print("Choose what you would like to do: ")
    print("1. Run an nmap scan. \n2. Analyze current network traffic on interface.\n3. Start automated scanning")
    inp = 0
    while True:                                                                                                         #Prompts the user for an option until they provide a valid one
        try:
            inp = int(input("> "))
            break
        except:
            print("Not a valid option.")
    match inp:
        case 1:
            arr = nmap()                                                                                                #Calls the nmap scan function
            print("Do you want to save your scan? ")
            if input("> ").lower().find("y") != -1:                                                                     #Asks the user if they want to save their scan, prompts them for a filename then attempts to write the data to that file, if everything works correctly, it will return to the menu
                print("Please enter the filename you would like to save your scan to: ")
                while True:
                    try:
                        name = input("> ")
                        with open(name, 'a') as f:
                            f.writelines(arr)
                        break
                    except:
                        print("Invalid name")
            main()
        case 2:                                                                                                         #Starts analyzing the network traffic
            print(f"Listening on {__Logger.INTERFACE}")
            print("Use ctrl - C to exit the capture")
            try:
                capture = sniff(iface=__Logger.INTERFACE, prn=packet_callback)                                          #Prints some info about the packets until the user presses ctrl-c
            except KeyboardInterrupt:
                pass
            print("Do you want to save your capture? ")                                                                 #Asks the user if they want to save their capture, prompts them for a filename then attempts to write the data to that file, if everything works correctly, it will return to the menu
            if input("> ").lower().find("y") != -1:
                print("What should the name of the file be?")
                while True:
                    name = input("> ")
                    try:
                        wrpcap(name, capture, append=True)                                                              #Saves our packets to the name the user provided, fails if the name is bad.
                        __c()
                        print("Saving file...")
                        time.sleep(2)                                                                                   #I know its not actually doing anything, but it gives the user a chance to read that everything had worked
                        break
                    except Exception as e:
                        print("Invalid name" + e)
            main()
        case 3:
            save = False                                                                                                #Starts the automated scanning with nmap
            name = None
            print("Would you like to save the results of the scan?")                                                    #If the user does, prompt them for the name of the file, and if the filename is valid, the program continues
            if input("> ").lower().find("y") != -1:
                save = True
                while True:
                    try:
                        print("What should the name of the file be?")
                        name = input("> ")
                        with open(name, 'a') as f:
                            f.write('')
                        break
                    except Exception as e:
                        print(e)
            while True:                                                                                                         #Prompts the user for how long the program should wait before scanning.
                try:
                    __c()
                    print("How often would you like to scan?")
                    print("Enter your times like Xd Xh Xm Xs (1d 13h 17m 54s) scans can take longer than the time provided")
                    inp = input("> ")
                    inp = inp.split(" ")                                                                                        #splits the input into sections based on the spaces used. 
                    seconds, minutes, hours, days = 0,0,0,0                                                                     #Sets all four to 0
                    for x in inp:                                                                                               #Loops through all the segments we created, and if they contain d h m s, the program saves that value to the appropriate variable.
                        if(x.lower().find("s") != -1):
                            seconds = int(x.replace("s", ""))
                        if(x.lower().find("m") != -1):
                            minutes = int(x.replace("m", ""))
                        if(x.lower().find("h") != -1):
                            hours = int(x.replace("h", ""))
                        if(x.lower().find("d") != -1):
                            days = int(x.replace("d", ""))
                    print(f"{days} days, {hours} hours, {minutes} minutes, {seconds} seconds")
                    print("Is this correct? Type yes to confirm.")
                    assert(input("> ").lower().find("y") !=-1)                                                                  #If the user messed up and wants to change their time, they can type no, this will error, and the prompt will restart
                    break                       
                except Exception as e:                                                                                          
                    print(e)
            print("Please enter your target host, press enter to use localhost")
            hostname = input("> ")
            if len(hostname.strip()) == 0:
                hostname = "localhost"
            print("Enter your arguments, per line, an example argument looks like \"-sV\" or \"-p 3389-4999\"")
            print("Press enter to finish your arguments")
            args = ["nmap"]                                                                                                     #Args is a list of all the things we will be running, nmap included
            args.append(hostname)

            while True:
                inp = input("> ")
                if len(inp.strip()) != 0:
                    args.append(inp)
                else:
                    break
            delay = seconds + minutes *60 + hours * 3600 + days * 86400                                                         #Calculate the correct amount of seconds to delay
            print("Please wait for the first scan to complete")
            nmap_thread = threading.Thread(target=loopNmap, args=(args, delay, save, name), daemon=True)                        #Creates the thread
            nmap_thread.start()                                                                                                 #Starts the thread
            main()                                                              

def __c():                              #This is a custom clear function designed to clear the terminal of output
    if os.name == "nt":
        os.system('cls')
    elif os.name == 'posix':
        os.system('clear')
    else:
        print(f"Clear is not supported on {os.name} ")

def main(choice: int = 0):              #Defines the main function, main does not need to be called with any arguments, however one can be passed to bypass the input check
    __c()
    print(f"""{__rgb.OKGREEN}  _       ____    _____   _____  ______  _____         __  ____    ___  
 | |     / __ \  / ____| / ____||  ____||  __ \       /_ ||___ \  / _ \ 
 | |    | |  | || |  __ | |  __ | |__   | |__) |______ | |  __) || | | |
 | |    | |  | || | |_ || | |_ ||  __|  |  _  /|______|| | |__ < | | | |
 | |____| |__| || |__| || |__| || |____ | | \ \        | | ___) || |_| |
 |______|\____/  \_____| \_____||______||_|  \_\       |_||____/  \___/ """) #ASCII art here https://patorjk.com/software/taag/#p=display&h=1&f=Big&t=LOGGER-130
    under = "_"*72+f"{__rgb.E}"
    if (__Logger.NMAPLOOP):
        under += f" Nmap running: [{__rgb.OKGREEN}\u2588{__rgb.E}]"
    else:
        under += f" Nmap running: [{__rgb.FAIL}\u2588{__rgb.E}]"
    print(under+'\n')
    print("Please choose an option. \n1. Analyze log file\n2. Analyze system performance. \n3. Security check\n4. Change options")
    
    while True:                     #If main was not called with a predetermined option, prompt the user for what they would like to do
        try:
            if choice == 0:
                choice = int(input(f"> "))        #Produce the input prompt.
            assert choice > 0  and choice < 6
            break
        except:
            print("Not a valid option")
    match choice:                       #Matches choice to a set case and calls the appropriate function. 
        case 1:
            analyze_log()
        case 2:
            analyze_system(emails=True)
        case 3:
            security_check()
        case 4:
            settings()
            
if __name__ == "__main__":              #Allows the program to be run, if parts of the program are implemented into other scripts, this wont be run
    main()                              #Calls main, I placed main into an actual function instead of placing it here to allow me to call it again if i need, or so other people can use the menu
