import sys
import os
import json
from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM

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

# Initialize the Mistral-7B model for text generation (used for both summarization and classification)
model_name = 'mistralai/Mistral-7B-Instruct-v0.3'

# Load the tokenizer and model
tokenizer = AutoTokenizer.from_pretrained(model_name, cache_dir=cache_dir)
model = AutoModelForCausalLM.from_pretrained(model_name, cache_dir=cache_dir)

# Initialize the text generation pipeline
generator = pipeline('text-generation', model=model, tokenizer=tokenizer)

# Function to process the ticket, summarize and classify tags
def process_ticket(ticket_id, title, body):
    # Create the prompt with the new structure
    prompt = f"Summarize the following ticket body in 1-2 sentences and assign the most relevant tag based on the title and content.\n\n"
    prompt += f"Title: {title}\nBody: {body}\n\n"
    prompt += f"Available tags: {', '.join(TAGS.keys())}\n"
    prompt += f"Response format: Summary: <summary_text> Tag: <most_relevant_tag>"
    
    # Generate the response from the model
    result = generator(prompt, max_length=350, num_return_sequences=1)

    # Extract the generated text from the result
    generated_text = result[0]['generated_text']
    
    # Split the response into summary and tag based on format
    try:
        summary_start = generated_text.find("Summary:") + len("Summary: ")
        tag_start = generated_text.find("Tag:") + len("Tag: ")

        summary_text = generated_text[summary_start:tag_start].strip()
        tag_text = generated_text[tag_start:].strip()

        # Ensure no extra spaces or unwanted text
        summary_text = summary_text.split("\n")[0]  # Take the first line as summary
        tag_text = tag_text.split("\n")[0]  # Take the first line as tag
    except ValueError:
        summary_text = "No summary available."
        tag_text = "GenericInformation"
    
    # Prepare the result in JSON format
    result_json = {
        'summary': summary_text,
        'id': ticket_id,
        'tag': tag_text
    }

    return json.dumps(result_json, indent=2)

if __name__ == "__main__":
    # Expecting the ticket info from command-line arguments
    ticket_id = sys.argv[1]
    title = sys.argv[2]
    body = sys.argv[3]
    
    # Process the ticket and print the result
    result = process_ticket(ticket_id, title, body)
    print(result)
