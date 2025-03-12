import re
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

# Function to clean the ticket body
def clean_ticket_body(text: str):
    # Remove or escape curly braces and square brackets
    cleaned_text = text.replace("{{", "").replace("}}", "").replace("[", "").replace("]", "")
    
    # Replace newline characters with space (or use other formatting as needed)
    cleaned_text = cleaned_text.replace("\n", " ")
    
    # Optionally, escape parentheses or remove them (depending on your needs)
    cleaned_text = re.sub(r'[\(\)]', '', cleaned_text)  # Removes parentheses
    
    # Optionally, escape quotes (double or single)
    cleaned_text = re.sub(r'["\']', '', cleaned_text)  # Removes quotes
    
    # Remove any extra whitespace (like tabs, multiple spaces, etc.)
    cleaned_text = ' '.join(cleaned_text.split())  # Removes excess whitespace
    
    return cleaned_text

# Define the prompt for summarization and tagging
def generate_prompt(title, body):
    return [
        {"role": "system", "content": "You are an AI that summarizes security tickets and assigns a single most relevant tag based on the title and body."},
        {"role": "user", "content": f"Title: {title}\nBody: {body}\n\n### TASK 1: Summarization\nSummarize the ticket body in 1-2 sentences.\n\n### TASK 2: Tagging\nChoose the **one best tag** from this list that matches the ticket:\n {TAGS}\n\nReturn output in JSON format with keys: 'summary' (ticket summary) and 'tag' (best matching tag)."}
    ]

# Function to summarize text using prompt
def summarize_text(title, body):
    prompt = generate_prompt(title, body)
    
    # Use the summarization pipeline (BART model for text generation) with the dynamic prompt
    summary = summarizer(
        prompt[1]['content'],  # Send the user content (the prompt)
        max_length=150,  # Set max length to 150 tokens
        min_length=10,   # Set min length to 50 tokens
        length_penalty=1.0,  # Keep summary length balanced
        do_sample=False,  # Ensure deterministic output
        truncation=True  # Truncate if text exceeds model token limit
    )
    return summary[0]['summary_text']

# Function to classify the most accurate tag based on the title and body
def classify_tag(title: str, body: str):
    combined_text = title + " " + body
    result = classifier(combined_text, candidate_labels=list(TAGS.keys()))
    return result['labels'][0]  # Return the most likely tag

# Function to process the ticket and return the output
def process_ticket(ticket_id, title, body):
    # Clean the body text to remove unwanted symbols
    body = clean_ticket_body(body)
    
    # Get the summary and tag based on the cleaned body and title
    summary = summarize_text(title, body)
    tag = classify_tag(title, body)

    # Prepare the result in JSON format
    result = {
        'summary': summary,
        'id': ticket_id,
        'tag': tag
    }

    return json.dumps(result, indent=2)

# Main execution
if __name__ == "__main__":
    ticket_id = sys.argv[1]
    title = sys.argv[2]
    body = sys.argv[3]

    result = process_ticket(ticket_id, title, body)
    print(result)
