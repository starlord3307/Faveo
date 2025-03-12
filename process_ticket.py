import sys
import os
import json
from transformers import pipeline, AutoTokenizer, AutoModelForSeq2SeqLM, AutoModelForSequenceClassification

# Set the cache directory to ensure the model is loaded from cache
cache_dir = os.path.expanduser("~/.cache/huggingface/transformers")

# Define the tags and their descriptions
TAGS = {
    "IPWhitelisting": "Adding IP addresses into Okta Security Networks fields if blocked.",
    "AppLocker": "Used when adding hashes to allow execution of applications (AppLocker or CrowdStrike).",
    "ADSecurityGroup": "Removing a user from an AD Security group to stop or allow access.",
    "AttachmentRelease": "Releasing an attachment if password protected.",
    "EmailWhitelisting": "Allowing emails through ProofPoint or Checkpoint for delivery.",
    "AppAssignment": "Adding a user to an Application.",
    "chatops:mfa-bypass": "Automates MFA AD group changes or Requests for the bypass MFA.",
    "VM": "Removing hosts from Nessus or decommissioning hosts from tracking in Nessus and Tenable.",
    "PhishingReport": "When a user submits a phishing report or requests email analysis.",
    "GenericInformation": "Generic tickets assigned to SecOps.",
    "PasswordReset": "When a ticket needs Okta or AD password reset.",
    "KeeperAccounts": "Issues with Keeper Password Manager accounts.",
    "MemberIssues": "Investigating possible security issues with Member accounts.",
    "ADPassword": "AD password issues, including resets.",
    "OktaMFAResets": "Okta MFA resets performed by Security or Requests for MFA reset.",
    "Zscaler": "Issues related to Zscaler security, domain allow/block requests.",
    "chatops:cs-usb": "Automates individual USB whitelisting.",
    "USBDeviceControl": "Requests for workstation USB whitelisting.",
    "Imperva": "Issues related to Imperva and CDN security."
}

# Initialize the pipelines
summarizer = pipeline('summarization',
                      model=AutoModelForSeq2SeqLM.from_pretrained('facebook/bart-large-cnn', cache_dir=cache_dir),
                      tokenizer=AutoTokenizer.from_pretrained('facebook/bart-large-cnn', cache_dir=cache_dir))

classifier = pipeline('zero-shot-classification',
                      model=AutoModelForSequenceClassification.from_pretrained('facebook/bart-large-mnli',
                                                                               cache_dir=cache_dir),
                      tokenizer=AutoTokenizer.from_pretrained('facebook/bart-large-mnli', cache_dir=cache_dir))


# Function to summarize text
def clean_ticket_body(text: str):
    # Remove non-text symbols like {{}} and [ ]
    cleaned_text = text.replace("{{", "").replace("}}", "").replace("[", "").replace("]", "")
    return cleaned_text

def summarize_text(text: str):
    # Clean the ticket body before summarization
    cleaned_text = clean_ticket_body(text)
    
    # Summarize the cleaned text
    summary = summarizer(cleaned_text, max_length=50, min_length=25, do_sample=False)
    return summary[0]['summary_text']



# Function to classify the most accurate tag based on the title and body
def classify_tag(title: str, body: str):
    combined_text = title + " " + body
    result = classifier(combined_text, candidate_labels=list(TAGS.keys()))
    return result['labels'][0]  # Return the most likely tag


# Function to process the ticket and return the output
def process_ticket(ticket_id, title, body):
    summary = summarize_text(body)
    tag = classify_tag(title, body)

    # Prepare the result in JSON format
    result = {
        'summary': summary,
        'id': ticket_id,
        'tag': tag
    }

    return json.dumps(result, indent=2)


if __name__ == "__main__":
    # Expecting the ticket info from command-line arguments
    ticket_id = sys.argv[1]
    title = sys.argv[2]
    body = sys.argv[3]

    # Process the ticket and print the result
    result = process_ticket(ticket_id, title, body)
    print(result)
