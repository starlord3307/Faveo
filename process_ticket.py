import json
from transformers import pipeline


def load_model():
    """Load the Mistral model for text generation."""
    return pipeline("text2text-generation", model="mistralai/Mistral-7B-Instruct-v0.2")


def summarize_and_tag(model, title, body):
    """Generate a summary and determine the most accurate tag."""
    tag_descriptions = {
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

    prompt = (
        f"Summarize the following ticket body in 1-2 sentences and assign the most relevant tag based on the title and content.\n\n"
        f"Title: {title}\nBody: {body}\n\n"
        f"Available tags: {', '.join(tag_descriptions.keys())}\n"
        f"Response format: Summary: <summary_text> Tag: <most_relevant_tag>"
    )

    response = model(prompt, max_length=200, do_sample=False)[0]['generated_text']

    # Extract summary and tag from model output
    summary, tag = response.split("Tag:") if "Tag:" in response else (response, "GenericInformation")
    summary = summary.replace("Summary:", "").strip()
    tag = tag.strip()

    # Validate tag
    return summary, tag if tag in tag_descriptions else "GenericInformation"


def process_ticket(ticket, model):
    """Processes a ticket and returns the summary and tag."""
    ticket_id = ticket.get("id", "")
    title = ticket.get("title", "")
    body = ticket.get("body", "")

    if isinstance(body, list):
        body = " ".join(body)  # Convert list to string if needed

    if not ticket_id or not title or not body:
        return {"error": "ID, Title, and Body are required."}

    summary, tag = summarize_and_tag(model, title, body)

    return {
        "id": ticket_id,
        "summary": summary,
        "tag": tag
    }


if __name__ == "__main__":
    try:
        # Load input JSON file
        with open("input.json", "r") as file:
            event_data = json.load(file)
        
        inputs = event_data.get("inputs", {})

        ticket_data = {
            "id": inputs.get("id", ""),
            "title": inputs.get("title", ""),
            "body": inputs.get("body", "")
        }

        model = load_model()
        result = process_ticket(ticket_data, model)

        # Print result in JSON format
        print(json.dumps(result))

    except Exception as e:
        print(json.dumps({"error": str(e)}))
