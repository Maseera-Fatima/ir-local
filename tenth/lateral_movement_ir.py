import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Set

# === CONFIGURATION ===
DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"
MAX_CHAIN_DEPTH = 2
CHAIN_TIME_WINDOW_MINUTES = 10
ALLOWLIST_FILE = "allowlist_actors.txt"
BREAKGLASS_USERS_FILE = "breakglass_users.txt"
ACTION_LOG = "lateral_movement_actions.log"

# Simulated role trust policies (role_arn -> set of allowed principals)
ROLE_TRUST_POLICIES = {
    "arn:aws:iam::111122223333:role/DevRole": {
        "arn:aws:iam::111122223333:user/developer",
        "arn:aws:iam::111122223333:user/compromised-user"  # for testing
    },
    "arn:aws:iam::444455556666:role/ProdAdmin": {
        "arn:aws:iam::111122223333:role/DevRole",
        "arn:aws:iam::444455556666:user/admin"
    }
}

# Simulated privileged roles
PRIVILEGED_ROLES = {
    "arn:aws:iam::444455556666:role/ProdAdmin"
}

def load_arn_set(filepath: str) -> Set[str]:
    if not os.path.exists(filepath):
        return set()
    with open(filepath, "r") as f:
        return {line.strip() for line in f if line.strip()}

# Load static lists
ALLOWLISTED_ACTORS = load_arn_set(ALLOWLIST_FILE)
BREAKGLASS_USERS = load_arn_set(BREAKGLASS_USERS_FILE)

def is_exempt_actor(actor_arn: str) -> bool:
    return actor_arn in BREAKGLASS_USERS or actor_arn in ALLOWLISTED_ACTORS

def parse_iso_datetime(dt_str: str) -> datetime:
    return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))

def is_privileged_role(role_arn: str) -> bool:
    return role_arn in PRIVILEGED_ROLES

def is_allowed_to_assume(role_arn: str, actor_arn: str) -> bool:
    allowed = ROLE_TRUST_POLICIES.get(role_arn, set())
    return actor_arn in allowed

def analyze_events(events: List[Dict]):
    """
    Analyze AssumeRole events to detect lateral movement.
    This version correctly handles role chaining by reconstructing chains.
    """
    # Filter and sort AssumeRole events by time
    assume_role_events = [
        e for e in events
        if e.get("eventName") == "AssumeRole"
        and e.get("userIdentity", {}).get("arn")
        and e.get("requestParameters", {}).get("roleArn")
    ]
    
    if len(assume_role_events) < 2:
        return
        
    try:
        assume_role_events.sort(key=lambda e: parse_iso_datetime(e["eventTime"]))
    except Exception as e:
        print(f"[ERROR] Failed to parse event times: {e}")
        return

    # Reconstruct chains by linking events where the actor of event N+1
    # is the assumed role of event N
    chains = []
    used_events = set()
    
    for i in range(len(assume_role_events)):
        if i in used_events:
            continue
            
        current_chain = []
        current_event = assume_role_events[i]
        current_actor = current_event["userIdentity"]["arn"]
        
        # Start a new chain
        current_chain.append({
            "actor": current_actor,
            "role": None,  # Original actor has no assumed role yet
            "event": current_event
        })
        
        # Try to extend the chain
        chain_index = i
        while chain_index < len(assume_role_events):
            current_event = assume_role_events[chain_index]
            assumed_role = current_event["requestParameters"]["roleArn"]
            
            # Add the role assumption to the chain
            current_chain.append({
                "actor": current_event["userIdentity"]["arn"],
                "role": assumed_role,
                "event": current_event
            })
            used_events.add(chain_index)
            
            # Look for next event in chain (where actor == assumed_role)
            next_found = False
            for j in range(chain_index + 1, len(assume_role_events)):
                if j in used_events:
                    continue
                next_event = assume_role_events[j]
                if next_event["userIdentity"]["arn"] == assumed_role:
                    chain_index = j
                    next_found = True
                    break
                    
            if not next_found:
                break
        
        # Only keep chains with at least MAX_CHAIN_DEPTH role assumptions
        role_assumptions = [step for step in current_chain if step["role"] is not None]
        if len(role_assumptions) >= MAX_CHAIN_DEPTH:
            chains.append(current_chain)

    # Analyze each detected chain
    for chain in chains:
        # Extract role assumptions (skip the original actor entry)
        role_assumptions = [step for step in chain if step["role"] is not None]
        
        # Check time window
        first_time = parse_iso_datetime(role_assumptions[0]["event"]["eventTime"])
        last_time = parse_iso_datetime(role_assumptions[-1]["event"]["eventTime"])
        time_delta = (last_time - first_time).total_seconds() / 60
        
        if time_delta > CHAIN_TIME_WINDOW_MINUTES:
            continue

        # Build analysis data
        original_actor = chain[0]["actor"]
        session_chain = [original_actor] + [step["role"] for step in role_assumptions]
        risk_factors = []
        is_cross_account = False
        original_account = original_actor.split(":")[4]

        # Analyze each role assumption in the chain
        for idx, step in enumerate(role_assumptions):
            role_arn = step["role"]
            actor_arn = step["actor"]
            event = step["event"]
            
            # Check cross-account
            role_account = role_arn.split(":")[4]
            if role_account != original_account:
                is_cross_account = True

            # Check if assumption was authorized
            if not is_allowed_to_assume(role_arn, actor_arn):
                risk_factors.append("unauthorized_assumption")

            # Check privilege escalation
            if is_privileged_role(role_arn):
                if idx == 0 and ":user/" in original_actor:
                    # Direct assumption by user
                    if not is_exempt_actor(original_actor):
                        risk_factors.append("direct_privileged_assumption")
                else:
                    # Escalation via chaining
                    risk_factors.append("privilege_escalation")

        # Add chain-specific risk factors
        if is_cross_account:
            risk_factors.append("cross_account_assumption")
            
        if len(role_assumptions) >= MAX_CHAIN_DEPTH:
            risk_factors.append("role_chaining")

        if not risk_factors:
            continue

        # Generate alert
        alert = {
            "alert_id": f"lateral-movement-{int(first_time.timestamp())}",
            "original_actor": original_actor,
            "assumed_role": session_chain[-1],
            "session_chain": session_chain,
            "event_time": role_assumptions[-1]["event"]["eventTime"],
            "source_ip": role_assumptions[-1]["event"].get("sourceIPAddress", "Unknown"),
            "is_cross_account": is_cross_account,
            "risk_factors": risk_factors
        }

        respond_to_alert(alert)

def revoke_user_credentials(user_arn: str):
    print(f"[ACTION] Deleting all access keys for user: {user_arn}")

def block_role_assumption(role_arn: str, actor_arn: str):
    print(f"[ACTION] Updating trust policy of {role_arn} to deny {actor_arn}")

def notify_secops(alert: Dict):
    message = (
        f"\n{'='*60}\n"
        f"LATERAL MOVEMENT VIA IAM ROLES ALERT\n"
        f"{'='*60}\n"
        f"Original Actor   : {alert['original_actor']}\n"
        f"Assumed Role     : {alert['assumed_role']}\n"
        f"Role Chain       : {' → '.join(alert['session_chain'][1:])}\n"
        f"Source IP        : {alert['source_ip']}\n"
        f"Event Time       : {alert['event_time']}\n"
        f"Cross-Account    : {'Yes' if alert['is_cross_account'] else 'No'}\n"
        f"Risk Factors     : {', '.join(alert['risk_factors'])}\n"
        f"Recommended      : Rotate user credentials, audit role trust policies\n"
        f"{'='*60}\n"
    )
    print(message)

def log_to_file(alert: Dict):
    filename = f"lateral_movement_{alert['alert_id']}.json"
    with open(filename, "w") as f:
        json.dump(alert, f, indent=2)
    print(f"[AUDIT] Full event logged to: {filename}")

    with open(ACTION_LOG, "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | {alert['alert_id']} | {alert['original_actor']} | {alert['assumed_role']} | {alert['risk_factors']}\n")

def respond_to_alert(alert: Dict):
    print(f"[ALERT] Lateral movement detected: {json.dumps(alert, indent=2)}")

    original_user = alert["original_actor"]
    if ":user/" not in original_user:
        print("[INFO] Original actor is not a user. Skipping key revocation.")
        return

    if is_exempt_actor(original_user):
        print(f"[INFO] Exempt actor {original_user}. Alert only.")
        notify_secops(alert)
        log_to_file(alert)
        return

    if not DRY_RUN:
        revoke_user_credentials(original_user)
        block_role_assumption(alert["assumed_role"], original_user)
    else:
        print("[DRY RUN] Would have revoked credentials and blocked role assumption.")

    notify_secops(alert)
    log_to_file(alert)

# === CLI INTERFACE ===
def main():
    if len(sys.argv) != 2:
        print("Usage: python lateral_movement_ir.py <cloudtrail_events.json>")
        print("\nExample cloudtrail_events.json (array of AssumeRole events):")
        print(json.dumps([
            {
                "eventName": "AssumeRole",
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::111122223333:user/compromised-user"
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::111122223333:role/DevRole"
                },
                "eventTime": "2025-10-24T14:20:00Z",
                "sourceIPAddress": "203.0.113.45"
            },
            {
                "eventName": "AssumeRole",
                "userIdentity": {
                    "type": "AssumedRole",
                    "arn": "arn:aws:iam::111122223333:role/DevRole"
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::444455556666:role/ProdAdmin"
                },
                "eventTime": "2025-10-24T14:22:00Z",
                "sourceIPAddress": "203.0.113.45"
            }
        ], indent=2))
        sys.exit(1)

    event_file = sys.argv[1]
    try:
        with open(event_file, "r") as f:
            events = json.load(f)
        if not isinstance(events, list):
            print("[ERROR] Input must be a JSON array of CloudTrail events.")
            sys.exit(1)
        analyze_events(events)
    except Exception as e:
        print(f"[ERROR] Failed to process events: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERROR] Script crashed: {e}")
        import traceback
        traceback.print_exc()
