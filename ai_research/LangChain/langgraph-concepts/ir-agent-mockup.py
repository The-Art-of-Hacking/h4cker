import operator
from typing import Annotated, List, Tuple, Union, Dict, Any
from datetime import datetime

from langchain_core.messages import BaseMessage, HumanMessage, ToolMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END

# --- 1. Define the Incident State ---
# This TypedDict will hold the state of our incident as it progresses through the graph.
# It includes a history of messages (for the LLM), the current alert,
# gathered evidence, identified IoCs, recommended actions, and the final report.
class IncidentState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    alert: Dict[str, Any]
    evidence: Dict[str, Any]
    iocs: List[str]
    recommended_actions: List[str]
    human_approved_actions: List[str]
    incident_report: str
    status: str # e.g., "new", "investigating", "awaiting_approval", "contained", "resolved"

# --- 2. Mock Security Tools ---
# These functions simulate interactions with various security tools.
# In a real scenario, these would make API calls to Splunk, EDR, Threat Intel, etc.

@tool
def splunk_search(query: str) -> str:
    """
    Simulates searching Splunk logs for a given query.
    Returns relevant log entries.
    Example query: "user login failures from IP 192.168.1.100"
    """
    print(f"\n--- TOOL CALL: Splunk Search ---")
    print(f"Query: {query}")
    if "unusual process execution" in query.lower() and "critical-server-01" in query.lower():
        return "Log: critical-server-01, user: svc_account, process: malicious.exe, parent: cmd.exe, network_conn: 10.0.0.50:443, timestamp: 2025-07-03T11:12:30Z"
    elif "login failures" in query.lower() and "192.168.1.100" in query.lower():
        return "Log: Multiple failed login attempts for user 'admin' from IP 192.168.1.100."
    else:
        return f"Splunk found no specific logs for: {query}. (Simulated)"

@tool
def edr_query(hostname: str, query_type: str) -> str:
    """
    Simulates querying an EDR (Endpoint Detection and Response) system.
    query_type can be "process_list", "network_connections", "file_changes".
    Returns relevant EDR data.
    """
    print(f"\n--- TOOL CALL: EDR Query ---")
    print(f"Hostname: {hostname}, Query Type: {query_type}")
    if hostname == "critical-server-01" and query_type == "process_list":
        return "EDR: Process 'malicious.exe' running, PID 1234, created by cmd.exe, user svc_account."
    elif hostname == "critical-server-01" and query_type == "network_connections":
        return "EDR: Outbound connection from malicious.exe (PID 1234) to 1.2.3.4:8080 (external C2)."
    else:
        return f"EDR found no specific data for {hostname}, {query_type}. (Simulated)"

@tool
def threat_intel_lookup(indicator: str) -> str:
    """
    Simulates looking up an indicator (IP, domain, hash) in a threat intelligence database.
    Returns threat intelligence context.
    """
    print(f"\n--- TOOL CALL: Threat Intel Lookup ---")
    print(f"Indicator: {indicator}")
    if indicator == "1.2.3.4":
        return "Threat Intel: IP 1.2.3.4 is known as a C2 server for 'APT29' group."
    elif indicator == "malicious.exe_hash":
        return "Threat Intel: Hash matches 'Ransomware_Variant_X'."
    else:
        return f"Threat Intel found no specific data for: {indicator}. (Simulated)"

@tool
def firewall_block_ip(ip_address: str) -> str:
    """Simulates blocking an IP address at the firewall."""
    print(f"\n--- TOOL CALL: Firewall Block IP ---")
    print(f"Blocking IP: {ip_address}")
    return f"Firewall: IP {ip_address} successfully blocked."

@tool
def iam_revoke_credentials(user_id: str) -> str:
    """Simulates revoking credentials for a compromised IAM user."""
    print(f"\n--- TOOL CALL: IAM Revoke Credentials ---")
    print(f"Revoking credentials for user: {user_id}")
    return f"IAM: Credentials for {user_id} successfully revoked."

@tool
def isolate_host(hostname: str) -> str:
    """Simulates isolating a compromised host from the network."""
    print(f"\n--- TOOL CALL: Isolate Host ---")
    print(f"Isolating host: {hostname}")
    return f"Network: Host {hostname} successfully isolated."

# List of all tools available to the agent
tools = [splunk_search, edr_query, threat_intel_lookup, firewall_block_ip, iam_revoke_credentials, isolate_host]

# --- 3. Define the LLM (Placeholder) ---
# In a real application, you would initialize your LLM here.
# For this example, we'll use a mock LLM that returns predefined responses
# or a simple echo for tool calls.
# from langchain_google_genai import ChatGoogleGenerativeAI
# llm = ChatGoogleGenerativeAI(model="gemini-pro", temperature=0)

# Mock LLM for demonstration purposes
class MockLLM:
    def invoke(self, messages: List[BaseMessage], tools: List = None) -> BaseMessage:
        last_message = messages[-1].content
        print(f"\n--- MOCK LLM INVOKED ---")
        print(f"Last message: {last_message}")

        # Simulate LLM deciding to call a tool
        if "unusual process execution" in last_message.lower() and "critical-server-01" in last_message.lower():
            return BaseMessage(
                content="",
                tool_calls=[
                    {"name": "splunk_search", "args": {"query": "unusual process execution on critical-server-01"}},
                    {"name": "edr_query", "args": {"hostname": "critical-server-01", "query_type": "process_list"}},
                    {"name": "edr_query", "args": {"hostname": "critical-server-01", "query_type": "network_connections"}}
                ]
            )
        elif "c2 server" in last_message.lower() and "1.2.3.4" in last_message.lower():
            return BaseMessage(
                content="",
                tool_calls=[
                    {"name": "firewall_block_ip", "args": {"ip_address": "1.2.3.4"}},
                    {"name": "isolate_host", "args": {"hostname": "critical-server-01"}},
                    {"name": "iam_revoke_credentials", "args": {"user_id": "svc_account"}}
                ]
            )
        elif "generate report" in last_message.lower():
            return BaseMessage(content="Report generation complete. Summary: Critical incident on critical-server-01 involving svc_account and C2 IP 1.2.3.4. Actions taken: host isolated, IP blocked, credentials revoked.")
        else:
            return BaseMessage(content=f"LLM Response: I am processing your request based on: {last_message}")

llm = MockLLM()

# Bind tools to the LLM for tool calling
# For a real LLM, you'd use llm.bind_tools(tools)
# For this mock, we'll handle tool calls manually in the investigation_node

# --- 4. Define Nodes (Agent Steps) ---

def alert_ingestion_node(state: IncidentState) -> IncidentState:
    """Simulates receiving and initial processing of an alert."""
    print("\n--- Node: Alert Ingestion ---")
    alert = state["alert"]
    print(f"Received alert: {alert['description']} on {alert['asset']}")
    return {
        "messages": [HumanMessage(content=f"New alert: {alert['description']} on {alert['asset']}. Initiate investigation.")],
        "status": "investigating"
    }

def investigation_node(state: IncidentState) -> IncidentState:
    """
    Uses the LLM to decide which tools to call for investigation and gathers evidence.
    This node acts as the 'brain' of the agent, deciding next steps.
    """
    print("\n--- Node: Investigation ---")
    messages = state["messages"]

    # In a real LangChain/LangGraph setup with a real LLM, the LLM would decide tool calls.
    # Here, we'll simulate that decision based on the alert.
    current_alert_desc = state["alert"]["description"].lower()
    current_asset = state["alert"]["asset"]
    
    new_evidence = state.get("evidence", {})
    new_iocs = state.get("iocs", [])
    tool_messages = []

    if state["status"] == "investigating":
        # Simulate LLM deciding to call tools based on the alert
        if "unusual process execution" in current_alert_desc:
            splunk_result = splunk_search.invoke({"query": f"unusual process execution on {current_asset}"})
            edr_process_result = edr_query.invoke({"hostname": current_asset, "query_type": "process_list"})
            edr_network_result = edr_query.invoke({"hostname": current_asset, "query_type": "network_connections"})

            new_evidence["splunk_logs"] = splunk_result
            new_evidence["edr_processes"] = edr_process_result
            new_evidence["edr_network"] = edr_network_result
            
            # Extract potential IoCs from simulated results
            if "1.2.3.4" in edr_network_result:
                new_iocs.append("1.2.3.4")
            if "malicious.exe" in edr_process_result:
                new_iocs.append("malicious.exe_hash") # Placeholder for actual hash
            if "svc_account" in splunk_result:
                new_iocs.append("svc_account")

            tool_messages.append(ToolMessage(content=splunk_result, tool_call_id="mock_splunk_1"))
            tool_messages.append(ToolMessage(content=edr_process_result, tool_call_id="mock_edr_1"))
            tool_messages.append(ToolMessage(content=edr_network_result, tool_call_id="mock_edr_2"))

            # If an IOC was found, simulate TI lookup
            if "1.2.3.4" in new_iocs:
                ti_result = threat_intel_lookup.invoke({"indicator": "1.2.3.4"})
                new_evidence["threat_intel_1.2.3.4"] = ti_result
                tool_messages.append(ToolMessage(content=ti_result, tool_call_id="mock_ti_1"))

            # After gathering initial evidence, the LLM would summarize or decide next steps
            llm_response = llm.invoke(messages + tool_messages + [HumanMessage(content="Summarize findings and assess impact.")])
            messages.append(llm_response)

    return {
        "messages": messages + tool_messages,
        "evidence": new_evidence,
        "iocs": new_iocs,
        "status": "investigated"
    }

def impact_assessment_node(state: IncidentState) -> IncidentState:
    """Assesses the impact of the incident based on gathered evidence."""
    print("\n--- Node: Impact Assessment ---")
    evidence = state["evidence"]
    iocs = state["iocs"]
    alert = state["alert"]

    impact_score = 0
    impact_summary = []

    if "critical-server-01" in alert["asset"]:
        impact_score += 5
        impact_summary.append("Critical asset involved.")
    if "1.2.3.4" in iocs and "C2 server" in evidence.get("threat_intel_1.2.3.4", ""):
        impact_score += 10
        impact_summary.append("Known C2 communication detected.")
    if "svc_account" in iocs:
        impact_score += 7
        impact_summary.append("Service account potentially compromised.")
    if "malicious.exe" in evidence.get("edr_processes", ""):
        impact_score += 8
        impact_summary.append("Malicious executable detected.")

    severity = "Low"
    if impact_score > 15:
        severity = "Critical"
    elif impact_score > 8:
        severity = "High"
    elif impact_score > 3:
        severity = "Medium"

    print(f"Impact Assessment: {severity} (Score: {impact_score}) - {', '.join(impact_summary)}")
    state["messages"].append(HumanMessage(content=f"Impact assessed as {severity}. Summary: {', '.join(impact_summary)}"))
    return {
        "messages": state["messages"],
        "status": "impact_assessed",
        "impact_severity": severity
    }

def containment_recommendation_node(state: IncidentState) -> IncidentState:
    """Recommends containment actions based on impact and IoCs."""
    print("\n--- Node: Containment Recommendation ---")
    iocs = state["iocs"]
    alert = state["alert"]
    recommended_actions = []

    if "1.2.3.4" in iocs:
        recommended_actions.append(f"Block IP 1.2.3.4 at firewall.")
    if "critical-server-01" in alert["asset"]:
        recommended_actions.append(f"Isolate host {alert['asset']}.")
    if "svc_account" in iocs:
        recommended_actions.append(f"Revoke credentials for svc_account.")
    if "malicious.exe_hash" in iocs:
        recommended_actions.append(f"Quarantine/delete malicious.exe on {alert['asset']}.")

    print(f"Recommended actions: {', '.join(recommended_actions)}")
    state["messages"].append(HumanMessage(content=f"Recommended actions: {', '.join(recommended_actions)}"))
    return {
        "messages": state["messages"],
        "recommended_actions": recommended_actions,
        "status": "awaiting_approval"
    }

def human_approval_node(state: IncidentState) -> IncidentState:
    """Simulates a human-in-the-loop approval step."""
    print("\n--- Node: Human Approval ---")
    print("\n--- HUMAN INTERVENTION REQUIRED ---")
    print("Review the following recommended actions:")
    for i, action in enumerate(state["recommended_actions"]):
        print(f"{i+1}. {action}")

    approved_actions = []
    while True:
        response = input("Approve all actions? (yes/no/list numbers to approve): ").lower().strip()
        if response == "yes":
            approved_actions = state["recommended_actions"]
            break
        elif response == "no":
            print("Actions not approved. Please specify which actions to approve or provide feedback.")
            # In a more complex scenario, you'd allow feedback to loop back to investigation
            break
        elif response.replace(',', '').isdigit():
            indices = [int(x.strip()) - 1 for x in response.split(',')]
            for idx in indices:
                if 0 <= idx < len(state["recommended_actions"]):
                    approved_actions.append(state["recommended_actions"][idx])
            print(f"Approved specific actions: {approved_actions}")
            break
        else:
            print("Invalid input. Please enter 'yes', 'no', or a comma-separated list of numbers.")

    if approved_actions:
        print("Human approved actions. Proceeding to execution.")
        return {
            "messages": state["messages"] + [HumanMessage(content="Human approved actions.")],
            "human_approved_actions": approved_actions,
            "status": "approved"
        }
    else:
        print("No actions approved or human intervention required for re-evaluation.")
        return {
            "messages": state["messages"] + [HumanMessage(content="Human did not approve actions. Re-evaluation needed.")],
            "status": "re_evaluate" # Custom status to indicate re-evaluation
        }

def action_execution_node(state: IncidentState) -> IncidentState:
    """Executes the human-approved containment actions."""
    print("\n--- Node: Action Execution ---")
    executed_results = []
    for action in state["human_approved_actions"]:
        if action["type"] == "block_ip":
            ip = action["parameters"]["ip_address"]
            result = firewall_block_ip.invoke({"ip_address": ip})
            executed_results.append(result)
        elif action["type"] == "isolate_host":
            hostname = action["parameters"]["hostname"].replace(".", "") # Remove dot for mock tool
            result = isolate_host.invoke({"hostname": hostname})
            executed_results.append(result)
        elif action["type"] == "revoke_credentials":
            user_id = action["parameters"]["user_id"].replace(".", "") # Remove dot for mock tool
            result = iam_revoke_credentials.invoke({"user_id": user_id})
            executed_results.append(result)
        # Add more action types as needed

    print(f"Executed actions: {executed_results}")
    state["messages"].append(HumanMessage(content=f"Executed actions: {executed_results}"))
    return {
        "messages": state["messages"],
        "status": "actions_executed",
        "execution_results": executed_results # Store results for report
    }

def report_generation_node(state: IncidentState) -> IncidentState:
    """Generates the final incident response report."""
    print("\n--- Node: Report Generation ---")
    report_content = f"""
Incident Response Report
Incident ID: IR-{datetime.now().strftime('%Y-%m-%d-%H%M%S')}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S EDT')}
Generated by: LangGraph Incident Response Agent (Sentinel)

1. Executive Summary
An incident involving {state['alert']['description']} on {state['alert']['asset']} was detected and responded to.
Impact Severity: {state.get('impact_severity', 'N/A')}

2. Timeline of Actions Taken
- Alert Detected: {state['alert']['description']} on {state['alert']['asset']} at {datetime.now().strftime('%H:%M:%S EDT')}
- Investigation Initiated: Agent started correlating logs and querying EDR/TI.
- Evidence Gathered:
    {state.get('evidence', {})}
- Identified IoCs: {', '.join(state.get('iocs', []))}
- Impact Assessed: {state.get('impact_severity', 'N/A')}
- Recommended Actions: {', '.join(state.get('recommended_actions', []))}
- Human Approval: {'Approved' if state.get('human_approved_actions') else 'Not Approved'}
- Actions Executed: {', '.join(state.get('human_approved_actions', []))}
- Execution Results: {state.get('execution_results', [])}

3. Root Cause Analysis Findings (Agent's Initial Assessment):
Based on the current evidence:
- Source of Compromise (potential): Unknown, but 'malicious.exe' and 'svc_account' activity observed.
- Attack Vector (potential): Lateral movement via compromised service account.
- Data at Risk (potential): Data on {state['alert']['asset']} and connected systems.

4. Recommendations (Agent's Suggestions for Improvement):
- Implement automated secret scanning in CI/CD pipelines.
- Enforce Multi-Factor Authentication (MFA) for all service accounts.
- Review and harden endpoint security configurations on critical assets.
- Conduct regular threat hunting for lateral movement techniques.
- Review firewall rules for outbound connections to unknown IPs.

This report provides an initial assessment and details automated actions. Further human forensic analysis is recommended.
    """
    print("\n--- Incident Report Generated ---")
    print(report_content)
    return {
        "messages": state["messages"] + [HumanMessage(content="Incident report generated.")],
        "incident_report": report_content,
        "status": "resolved"
    }

# --- 5. Define the Graph ---

# Define the graph
workflow = StateGraph(IncidentState)

# Add nodes to the graph
workflow.add_node("alert_ingestion", alert_ingestion_node)
workflow.add_node("investigation", investigation_node)
workflow.add_node("impact_assessment", impact_assessment_node)
workflow.add_node("containment_recommendation", containment_recommendation_node)
workflow.add_node("human_approval", human_approval_node)
workflow.add_node("action_execution", action_execution_node)
workflow.add_node("report_generation", report_generation_node)

# Set the entry point
workflow.set_entry_point("alert_ingestion")

# Define the edges (workflow transitions)
workflow.add_edge("alert_ingestion", "investigation")
workflow.add_edge("investigation", "impact_assessment")
workflow.add_edge("impact_assessment", "containment_recommendation")

# Conditional edge for human approval
workflow.add_conditional_edges(
    "human_approval",
    lambda state: state["status"], # Based on the status returned by human_approval_node
    {
        "approved": "action_execution",
        "re_evaluate": "investigation" # Loop back to investigation if human wants re-evaluation
    }
)

workflow.add_edge("containment_recommendation", "human_approval")
workflow.add_edge("action_execution", "report_generation")

# Set the finish point
workflow.add_edge("report_generation", END)

# Compile the graph
app = workflow.compile()

# --- Run the Agent ---

if __name__ == "__main__":
    # Example 1: Simulate a critical alert
    initial_alert = {
        "id": "ALERT-001",
        "description": "Unusual Process Execution",
        "asset": "critical-server-01",
        "timestamp": datetime.now().isoformat()
    }

    print("\n--- Running Incident Response Agent for ALERT-001 ---")
    final_state = None
    for s in app.stream({
        "messages": [],
        "alert": initial_alert,
        "evidence": {},
        "iocs": [],
        "recommended_actions": [],
        "human_approved_actions": [],
        "incident_report": "",
        "status": "new"
    }):
        if "__end__" not in s:
            print(f"\n--- Current State: {s}")
            final_state = s
        else:
            final_state = s["__end__"]

    print("\n--- Incident Response Process Completed ---")
    print(f"Final Status: {final_state.get('status', 'N/A')}")
    # print(f"Final Report:\n{final_state.get('incident_report', 'No report generated.')}")

    # You can also inspect the graph visualization (requires graphviz installed)
    # from IPython.display import Image, display
    # display(Image(app.get_graph().draw_mermaid_png()))
