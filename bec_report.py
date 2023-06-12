import sys
import os
from docx import Document
from datetime import date
import argparse

parser = argparse.ArgumentParser(description='Generate report from given data.')
parser.add_argument('-CurrPath', type=str, required=True, help='The current path.')
parser.add_argument('-User', type=str, required=True, help='The user email.')
parser.add_argument('-Company', type=str, required=True, help='The company name.')
parser.add_argument('-Ticket', type=str, required=True, help='The ticket.')

args = parser.parse_args()

currpath = args.CurrPath
user = args.User
company = args.Company
ticket = args.Ticket

# Get the data from arguments
bec_incident = "Business Email Compromise - " + user
bec_company = company
bec_ticket = ticket

# Template path
template_path = os.path.join(currpath, 'BEC_IR_REPORT.docx')

# Open the Word document template
document = Document(template_path)

# Prompt the user for other details
incident_owner = input("Incident Owner: Enter your name: ")
incident_time = input("Initial Incident time: ")
completion_date = date.today().strftime("%B %d, %Y")
severity = input("Incident Severity Level (High, Medium, Low): ").lower()
severity_comments = input("Enter any comments regarding severity: ")

# Incident Type
additional_comments = input("Incident Type: Enter any additional comments ")

# IR Timeline
alert_discovered = input("Initial Alert Time: ")
secured_time = input("Time User's Account was Secured: ")
secured_notes = input("Note for securing account: ")
completed_time = input("Incident Closure Time: ")

# Impact
other_parties = input("Enter any other affected parties (if any): ")
additional_details = input("Enter any additional details: ")

# Security Recommendations
sec_recommend = input("Security Recommendation: ")


for table in document.tables:
    for row in table.rows:
        for cell in row.cells:
            cell.text = cell.text.replace('[BEC_INCIDENT]', bec_incident)
            cell.text = cell.text.replace('[BEC_COMPANY]', bec_company)
            cell.text = cell.text.replace('[INCIDENT_OWNER]', incident_owner)
            cell.text = cell.text.replace('[COMPLETION_DATE]', completion_date)
            cell.text = cell.text.replace('[BEC_TICKET]', bec_ticket)
            cell.text = cell.text.replace('[SEVERITY_COMMENTS]', severity_comments)
            cell.text = cell.text.replace('[ADDITIONAL_DETAILS]', additional_details)
            cell.text = cell.text.replace('[INCIDENT_TIME]', incident_time)
            cell.text = cell.text.replace('[ALERT_DISCOVERED]', alert_discovered)
            cell.text = cell.text.replace('[SECURED_TIME]', secured_time)
            cell.text = cell.text.replace('[SECURED_NOTES]', secured_notes)
            cell.text = cell.text.replace('[COMPLETED_TIME]', completed_time)
            cell.text = cell.text.replace('[OTHER_PARTIES]', other_parties)
            cell.text = cell.text.replace('[ADDITIONAL_DETAILS]', additional_details)
            cell.text = cell.text.replace('[SEC_RECOMMEND]', sec_recommend)
            
            if '[H]' in cell.text and severity == "high":
                cell.text = cell.text.replace('[H]', 'X')
            elif '[M]' in cell.text and severity == "medium":
                cell.text = cell.text.replace('[M]', 'X')
            elif '[L]' in cell.text and severity == "low":
                cell.text = cell.text.replace('[L]', 'X')
            else:
                cell.text = cell.text.replace('[H]', '')
                cell.text = cell.text.replace('[M]', '')
                cell.text = cell.text.replace('[L]', '')


        

# Set the output path as the current directory
output_path = os.path.join(os.getcwd(), f'{bec_company}_IR_REPORT.docx')

# Save the modified document with recipient details and date
document.save(output_path)
