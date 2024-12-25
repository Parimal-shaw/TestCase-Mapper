from burp import IBurpExtender,ITab, IMessageEditorTab
from javax.swing import Box, BoxLayout, JButton, JLabel, JPanel, JFrame, JScrollPane, JCheckBox, BoxLayout, JSeparator, JFileChooser
from java.awt import GridBagLayout, GridBagConstraints
from java.awt import Component
##from java.awt import FlowLayout 
from java.io import BufferedReader, FileReader, File
from javax.xml.parsers import DocumentBuilderFactory
from org.w3c.dom import Document
from org.xml.sax import InputSource
import re
import json
import time
from java.awt import Dimension
from java.lang import Short
from java.awt import Component
import xml.etree.ElementTree as trees

class BurpExtender(IBurpExtender, ITab, IMessageEditorTab):

    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set the extension name
        callbacks.setExtensionName("Testcase Mapper")

        # perform other extension setup here

        print("Extension loaded successfully")
        
        # Create a GUI component for the custom tab
        
        
        #self._tab_component = JPanel(FlowLayout())
        self._tab_component = JPanel()
        self._tab_component.setLayout(BoxLayout(self._tab_component, BoxLayout.Y_AXIS))
        #self._tab_component.add(Box.createVerticalGlue())
        
        #Adding button in UI
        labels_and_buttons = [
            JLabel("Select your MM file"),
            JButton("Select your MM file", actionPerformed=self.selectFile),
            JButton("Print to MM file", actionPerformed=self.onclick),
            JButton("Reset Selection", actionPerformed=self.deselect)
            ]
        #Demo UI     
        self._tab_component.add(JLabel("Testcase Mapper"))
       
        self._tab_component.setLayout(GridBagLayout())
        
        c = GridBagConstraints()
        c.gridx = 0
        c.gridy = 0
        
        for component in labels_and_buttons:
            component.setAlignmentX(Component.RIGHT_ALIGNMENT)
            self._tab_component.add(component, c)
            
            c.gridx += 1
            if c.gridx > 1:
                c.gridx = 0
                c.gridy += 1
        
        
        # Adding checkboxes
        self.checkboxes = [] 
        #*******************************Add The Name of the Vulnerability Below to add button in Burp UI*******************************
        
        testcase = ["Login","Logout","Session","Post-Login","Authorization","Pre-Login","Json Web Token(JWT)","Forgot Password/Reset Password","Change Password","File-Upload","Single-Sign On(SSO)","Server Side Javascript Injection (SSJI)","Cross Site Scripting(XSS)","SQli","NoSQli","Server Side Template Injection(SSTI)","Cross-Site Request Forgery(CSRF)","Missing Several Security Headers","Insecure Response Header","Server-Side Request Forgery","IDOR","Privelege Escalation","Unauthorize Access","2FA/OTP","Email","SMS","HTTP Parameter Polution(HPP)","Prototype Pollution","Cross-Origin Resource Sharing(CORS)","Deserialization","Carriage Return and Line Feed(CRLF)","Web Cache Poisoning","Captcha","Client Side Template Injection(CSTI)","ClickJacking","HTTP Request Smuggling/HTTP Desync","HTTP Response Smuggling","Response Manipulation","LDAP Injection","Open Redirection","Race Condition","Xpath Injection","XML External Entity(XXE)","Integer Overflow","File Inclusion/Path Traveral","Dependency Confusion","Account Takeover","Domain/Subdomain Takeover","Stack Trace Error","Server Side Inclusion"]
        
        '''
        #Test cases Numbering
        1 - Login
        2 - Logout
        3 - Session
        4 - Post-Login
        5 - Authorization
        6 - Pre-Login
        7 - Json Web Token(JWT)
        8 - Forgot Password/Reset Password
        9 - Change Password
        10 - File-Upload
        11 - Single-Sign On(SSO)
        12 - Server Side Javascript Injection (SSJI)
        13 - Cross Site Scripting(XSS)
        14 - SQli
        15 - NoSQli
        16 - Server Side Template Injection(SSTI)
        17 - Cross-Site Request Forgery(CSRF)
        18 - Missing Several Security Headers
        19 - Insecure Response Header
        20 - Server-Side Request Forgery
        21 - IDOR
        22 - Privelege Escalation
        23 - Unauthorize Access
        24 - 2FA/OTP
        25 - Email
        26 - SMS
        27 - HTTP Parameter Polution(HPP)
        28 - Prototype Pollution
        29 - Cross-Origin Resource Sharing(CORS)
        30 - Insecure Deserialization
        31 - Carriage Return and Line Feed(CRLF)
        32 - Web Cache Poisoning
        33 - Captcha
        34 - Client Side Template Injection(CSTI)
        35 - ClickJacking
        36 - HTTP Request Smuggling/HTTP Desyn
        37 - HTTP Response Smuggling
        38 - Response Manipulation
        39 - LDAP Injection
        40 - Open Redirection
        41 - Race Condition
        42 - Xpath Injection
        43 - XML External Entity(XXE)
        44 - Integer Overflow
        45 - File Inclusion/Path Traveral
        46 - Dependency Confusion
        47 - Account Takeover
        48 - Domain/Subdomain Takeover
        49 - Stack Trace Error
        50 - Server Side Inclusion
        
        '''
        # Use a JPanel with BoxLayout and add checkboxes vertically
        self._tab_component.setLayout(GridBagLayout())
        
        # Add checkboxes in two columns
        for i in range(len(testcase)):
            checkbox = JCheckBox("{}".format(testcase[i]))
            self.checkboxes.append(checkbox)
            self._tab_component.add(checkbox, c)
            

            c.gridx += 2
            if c.gridx > 4:
                c.gridx = 0
                c.gridy += 1
                
        

        '''for i in testcase:
            checkbox = JCheckBox("{}".format(i))
            #checkbox.setMaximumSize(Dimension(Short.MAX_VALUE, checkbox.getPreferredSize().height))
            checkboxes.append(checkbox)
            #self._tab_component.add(checkbox)

        for checkbox in checkboxes:
            checkbox.setAlignmentX(Component.CENTER_ALIGNMENT)
            self._tab_component.add(checkbox)
        
        self._tab_component.add(Box.createVerticalGlue())'''
        
        # Use JScrollPane to allow scrolling
        scroll_pane = JScrollPane(self._tab_component)
        scroll_pane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)

        #**************************To Added Test Cases(Continue from the last number)**************************
        '''self.test_cases = {
            "key1": "sqli",
            "13": "Cross Site Scripting(XSS)",
            "14": {"1":"SQL Injection","2":"Time Based Sqli","3":"Union Based Sqli","4":"Condition Based Sqli"},
            "key4":"authorization bypass",
            "key5":"weak token",
            "key6":"repeated token"
            }'''
        
       
        self.test_cases = {
            "1":{"100":"Login","2":"No Rate Limiting Implemented/No account Locakout","3":"Username Enumeration","4":"Sqli","5":"Partial Password Accepted","6":"Password Case insensitive accepted","7":"Cross-Site Scripting (XSS)","8":"Password Autocomplete Enabled","9":"Default Username and Password Accepted","10":"Open Url Redirection","11":"Response Maniputlation","12":"Host Header Injection","13":"Http Parameter Pollution (HPP)"},
            "2":{"101":"Logout","2":"Session Valid After Logout","3":"Parameter tempering","4":"BackButton Browsing","5":"Open Redirection","6":"CSRF","7":"Cross-Site Scripting (XSS)"},
            "3":{"102":"Session","2":"Session Prediction","3":"Session Fixation","4":"Static token for login","5":"NonHTTPOnly Session Cookie","6":"Unsecured Session Cookie","7":"Access token stored in localstorage","8":"Cookie Path Traversal","9":"perform privileged actions with unprivileged user cookie","10":"Reuse cookie","11":"session valid more than 24hrs"},
            "4":{"103":"Post login","2":"Force Browsing","3":"IDOR","4":"XSS","5":"SQLi","6":"Verbose error","7":"Privilege escalation","8":"Cookie Path Traversal","9":"perform privileged actions with unprivileged user cookie","10":"Reuse cookie","11":"session valid more than 24hrs"},
            "5":"Authorization",
            "6":{"105":"Pre-Login","2":"Host header Injection","3":"Server Remote version disclosure","4":"Options Method Enabled","5":"Open redirection","6":"V-Host misconfiguration","7":"Trace method enabled","8":"Crossite Tracing with override method","9":"SSL not enforced","10":"Stack trace error enabled","10":"Misconfigured CORS","11":"Directory list enabled","12":"Verbose Error enabled","13":"DNS zone transfer","14":"Dangling DNS Pointer","15":"Path traversal","17":"Content Spoofing for 500 error","18":"Sensitive data stored in source code","19":"HTML 5 Storage Manipulation"},
            "7":{"100":"Sensitive information in JWT token","2":"JWT None-signing Algo is allowed","3":"JWT Invalid Signature Allowed","4":"Secret key is Leaked of JWT token","5":"Server never checks secret of JWT","6":"JWT weak HMAC secret","7":"JWT Token Never Expiring","8":"JWT Token generated on client-side","9":"JWKS Spoofing","10":"JWT stored in local storage","11":"JWT token recreate token","999":None},
            "8":{"107":"Forgot Password/Reset Password","2":"Username enumeration","3":"Account accessible after reset in different browser","4":"XSS (Forgot Username / Password)","5":"SQLi (Forgot Username / Password)","6":"Password Reset Email (current password)","7":"Email Flooding","8":"email bounce","9":"Add email parameter of another user and check","10":"Blank password change","11":"Token uniqueness","12":"SSTI"},
            "9":{"108":"Change Password","2":"Blank password change","3":"Verbose error","4":"Host header injection","5":"Password history check","6":"Failed to check invalid session after password change","7":"Partial Password","8":"Try long password","9":"Current Password Bypass","10":"Weak Password Policy","11":"Remove Parameter and check","12":"Sensitive Data in GET Parameter","13":"Bruteforce Old Password","14":"Bruteforce Username"},
            "10":{"109":"File Upload","2":"Null characters at the End","3":"Special character in between extension","4":"Bypass Content type","5":"Image tragick","6":"Path Traversal","7":"File upload overwrite","8":"Empty extension","9":"Empty filename","10":"symlink","11":"XSS via File name","12":"XSS File content","13":"SQLi via File name","14":"SQLi Content","15":"CSV Injection"},
            "11":{"110":"Single Sign on(SSO)","2":"CSRF","3":"Reusable Authentication Token","4":"Login via test microsoft/outlook account and see what is the response","5":"Change the response and see if you are able to bypass","6":"Open Redirection in redirect_uri"},
            "12":"Server Side Javascript Injection (SSJI)",
            "13":{"1":"Cross site scripting","2":"Reflected Cross-Site Scripting","3":"Stored Cross-Site Scripting","4":"Document Object Model (DOM)","5":None},
            "14":{"1":"SQL injection","2":"Error-Based SQL Injection","3":"Union-Based SQL Injections","4":"Blind Boolean-based SQL Injection","5":"Blind Time-Based SQL Injection","6":None},
            "15":{"1":"NoSql injection","2":"NoSQL syntax injection","3":"NoSQL operator injection","4":"Timing based injection","5":None},
            "16":"Server Side Template Injection(SSTI)",
            "17":"Cross-Site Request Forgery(CSRF)",
            "18":{"1":"Missing Several Security Headers","2":"Strict-Transport-Security","3":"X-Frame-Options","4":"X-Content-Type-Options","5":"Content-Security-Policy","7":"https://domsignal.com/toolbox","8":None},
            "19":{"1":"Insecure Response Header","3":"Pragma","4":"Server","5":"X-AspNet-Version","7":"https://owasp.org/www-project-secure-headers/ci/headers_remove.json","8":None},
            "20":{"1":"Server-Side Request Forgery","2":"Blind SSRF","3":"Semi-Blind SSRF","4":"Non-Blind SSRF","5":None},
            "21":"IDOR",
            "22":"Privilege Escalation",
            "23":"Unauthorize Access/Forced Browsing",
            "24":{"123":"2FA/OTP","2":"Brute Force on OTP","3":"Null Characters","4":"HPP on mobile number","5":"otp brute force using json array","6":"Mobile Number Enumeration","7":"Reuse Old OTP","8":"OTP of another user","9":"OTP expiration","10":"Default OTP","11":"HTML Injection","12":"Send two user otp and use other user OTP which is the latest one","13":"OTP Local Storage ","14":"SSTI"},
            "25":{"124":"Email","2":"SSTI","3":"Email Flooding","4":"Token Manipulation"},
            "26":{"125":"SMS","2":"SSTI","3":"SMS Flooding","4":"Command injection","5":"OSS Penetration","6":"SMS SPAM","7":"SMS Crash","8":"SMS Spoofing","9":"SMS Snooping","10":"Buffer Overflow Attack","11":"DOS Attack"},
            "27":"HTTP Parameter Polution(HPP)",
            "28":{"1":"Prototype Pollution","2":"Prototype pollution via the URL","3":"Prototype pollution via JSON input","4":None},
            "29":"Cross-Origin Resource Sharing(CORS)",
            "30":"Insecure Deserialization",
            "31":"Carriage Return and Line Feed(CRLF)",
            "32":"Web Cache Poisoning",
            "33":{"132":"Captcha","2":"Captcha process bypass","3":"NULL Captcha","4":"Double parameter in captcha","5":"reuse captcha"},
            "34":"Client Side Template Injection(CSTI)",
            "35":"ClickJacking",
            "36":"HTTP Request Smuggling/HTTP Desync",
            "37":"HTTP Response Smuggling",
            "38":"Response Manipulation",
            "39":"LDAP Injection",
            "40":"Open Redirection",
            "41":"Race Condition",
            "42":"Xpath Injection",
            "43":{"1":"XML External Entity(XXE)","2":"XXE to retrieve files","3":"XXE to SSRF","4":"Blind XXE","5":"XXE via file upload","6":"XXE via modified content type","7":None},
            "44":"Integer Overflow",
            "45":"File Inclusion/Path Traveral",
            "46":"Dependency Confusion",
            "47":"Account Takeover",
            "48":"Domain/Subdomain Takeover",
            "49":"Stack Trace Error",
            "50":"Server Side Inclusion",
            "51":"Open Url"
            }
        
        # Register the custom tab
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Testcase Mapper"

    def getUiComponent(self):
         return self._tab_component

    def __init__(self):
        # Initialize the instance variabl
        self._file_content = None

    def selectFile(self, event):
        # Create a file chooser
        file_chooser = JFileChooser()
        
        # Set the file chooser to select files only (not directories)
        file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)

        # Show the file chooser dialog
        result = file_chooser.showOpenDialog(None)
        
        # Check if a file was selected
        if result == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile()
            print("Selected File: {}".format(selected_file))
            #self._tab_component.add(JLabel("Selected File: {}".format(selected_file)))
            self._selected_file = file_chooser.getSelectedFile().getAbsolutePath()
            # Read the content of the selected file
            self._file_content = self.readFromFile(selected_file)
            #self._tab_component.add(JLabel("File Content:\n{}".format(self._file_content)))
        else:
            #self._tab_component.add(JLabel("File selection cancelled."))  
            print("File Selection Cancelled")
    
    def readFromFile(self, file):
        content = ""
        try:
            # Use BufferedReader to read the file content
            reader = BufferedReader(FileReader(file))
            line = reader.readLine()
            while line is not None:
                content += line + "\n"
                line = reader.readLine()
                #print(line)
            reader.close()
        except Exception as e:
            print("Error reading file: {}".format(e))
        return content

    def deselect(self,checkbox):
         for checkbox in self.checkboxes:
            checkbox.setSelected(False)

    
    def onclick(self, file_path):
        base = "Test Case" 
        
        
        selected_checkboxes = [i for i, checkbox in enumerate(self.checkboxes, start=1) if checkbox.isSelected()]
        
        #print(selected_checkboxes)
        #for reading file
        #pattern = re.compile('</node>')
        '''def split_and_keep(string, pattern):
            return [newline for newline in pattern.split(string) if newline]'''

        with open(self._selected_file, 'r') as file_handle:
            lines = file_handle.readlines()
            #print('this is full list from file')
            #print(lines)
            result = []
            #pattern = re.compile(r'</node>\n$')
            for newline in lines:        
                if '</node>' in newline:
                    #print('before spliting')
                    #print(newline)
                    if '</node>\n' == newline:
                        result.append(newline)
                    else:
                        #print('else was triggerd')
                        newst = re.split('</node>',newline)
                        #print('after spliting')
                        #print(newst)
                        for newlist in newst:
                            #print('processing')
                            #print(newlist)
                            newsub = re.sub('^$','</node>\n',newlist)
                            result.append(newsub)
                            #print(newsub)
                            #print('replace')
                        
                else:
                    result.append(newline)
            #print('this is result')        
            #print(result)

            #self._tab_component.add(JLabel(lines))
            list_mindmap = []
            for line in result:
                list_mindmap.append(line)

            if '<icon BUILTIN="idea"/>\n' in list_mindmap:
                li= list_mindmap.index('<icon BUILTIN="idea"/>\n')
                print(li)
                list_mindmap.insert(li+5,"<node TEXT=\"Test cases\">\n<font BOLD=\"true\" NAME=\"SansSerif\" SIZE=\"12\"/>\n")
                #if you request has get and post both the Data increase the Value of i by 1
                i = 5
                #**********************************Do not Tamper with the Below Code**********************************
                nonnested = ["1","2","3","4","6","7","8","9","10","11","24","25","26","33"]
                nested = ["13","14","15","20","28","43"]
                links = ["18","19"]

                for x in selected_checkboxes:
                    all_iterations_completed = False
                #************************Only Add the Value for STr(x) if nested test cases***************************
##################################################################################################################################                
                    if str(x) in nonnested:
                        for y in self.test_cases[str(x)]:
                            #print("if nonnested is triggered")
                            if str(y) == "1":
                                i = i + 1
                                list_mindmap.insert(li+i,"<node TEXT=\"{}\">\n".format(self.test_cases[str(x)][y]))
                            else:
                                i = i + 1
                                list_mindmap.insert(li+i,"<node TEXT=\"{}\"/>\n".format(self.test_cases[str(x)][y]))
                            #list_mindmap.insert(li+i+1,"</node>\n")
 ###################################################################################################################################                   
                    #below code need to be fix
                    elif str(x) in nested:
                        index = 0    
                        for y in self.test_cases[str(x)]:
                            index = index + 1
                            #print(str(index))
                            if str(y) == "1":
                                i = i + 1
                                list_mindmap.insert(li+i,"<node TEXT=\"{}\">\n".format(self.test_cases[str(x)][y]))
                            
                            elif str(y) != "1":
                                #print(str(self.test_cases[str(x)][y]))
                                i = i + 1
                                if self.test_cases[str(x)][y] == None:
                                    pass
                                else:
                                    list_mindmap.insert(li+i,"<node TEXT=\"{}\"/>\n".format(self.test_cases[str(x)][y]))
                            
                            else:
                                print(str(self.test_cases[str(x)][y]))
                                i = i + 1
                                if self.test_cases[str(x)][y] == None:
                                    pass
                                else:
                                    list_mindmap.insert(li+i,"<node TEXT=\"{}\"/>\n".format(self.test_cases[str(x)][y]))
                                
                            if index == len(self.test_cases[str(x)]):
                                    #print("value of index" + str(index))
                                    #print("value of length" + str(len(self.test_cases[str(x)])))
                                    all_iterations_completed = True
                                    #print("if index was triggered")
                                
                            if all_iterations_completed:
                                #list_mindmap.insert(li+i,"<node TEXT=\"{}\"/>\n".format(self.test_cases[str(x)][y]))
                                list_mindmap.insert(li + i, "</node>\n")
                                #print("adding closing node")
                            
                            else:
                                pass
##################################################################################################################################          
                    elif str(x) in links:
                        index = 0    
                        for y in self.test_cases[str(x)]:
                            index = index + 1
                            #print(str(index))
                            if str(y) == "1":
                                i = i + 1
                                list_mindmap.insert(li+i,"<node TEXT=\"{}\">\n".format(self.test_cases[str(x)][y]))
                            
                            elif str(y) != "1":
                                #print(str(self.test_cases[str(x)][y]))
                                i = i + 1
                                if self.test_cases[str(x)][y] == None:
                                    pass
                                elif str(y) == "7":
                                    list_mindmap.insert(li+i,"<node LINK=\"{}\" TEXT=\"Double Click Here For More\"/>\n".format(self.test_cases[str(x)][y]))
                                else:
                                    list_mindmap.insert(li+i,"<node TEXT=\"{}\"/>\n".format(self.test_cases[str(x)][y]))
                            
                            else:
                                print(str(self.test_cases[str(x)][y]))
                                i = i + 1
                                if self.test_cases[str(x)][y] == None:
                                    pass
                                else:
                                    list_mindmap.insert(li+i,"<node TEXT=\"{}\"/>\n".format(self.test_cases[str(x)][y]))
                                
                            if index == len(self.test_cases[str(x)]):
                                    #print("value of index" + str(index))
                                    #print("value of length" + str(len(self.test_cases[str(x)])))
                                    all_iterations_completed = True
                                    #print("if index was triggered")
                                
                            if all_iterations_completed:
                                #list_mindmap.insert(li+i,"<node TEXT=\"{}\"/>\n".format(self.test_cases[str(x)][y]))
                                list_mindmap.insert(li + i, "</node>\n")
                                #print("adding closing node")
                            
                            else:
                                pass
##################################################################################################################################                              
                    else:
                        #print("else condition was triggered")
                        i = i + 1
                        list_mindmap.insert(li+i,"<node TEXT=\"{}\"/>\n".format(self.test_cases[str(x)]))
                #print("closing test cases node")
                list_mindmap.insert(li+i+1,"</node>\n")
                #print(list_mindmap)
                with open(self._selected_file, 'w') as file_handle:
                    for new_lines in list_mindmap:
                        file_handle.write(str(new_lines))
                        #print(str(new_lines))
                        #previous code
                #**********************************Do not Tamper with the Above Code**********************************
                ###Created By: Parimal Shaw
                ##Contributed By: Anik Jain