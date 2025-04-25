import logging
import sys
import time
from core.firewall_rules import add_rule, rule_exists
from core.utils import checkPrivileges

# Configure logging to console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('test_add_rule')

def test_add_rule():
    """Test adding a firewall rule without deleting it"""
    
    print("=== FIREWALL RULE ADD TEST ===")
    
    # Check administrator privileges
    if not checkPrivileges():
        print("[ERROR] This test requires administrator privileges. Please run as administrator.")
        return False
    
    print("[OK] Admin privileges confirmed")
    
    # Create a unique rule name with timestamp
    test_rule_name = f"TestRule_{int(time.time())}"
    print(f"Creating test rule: {test_rule_name}")
    
    # Define rule parameters
    test_rule = {
        'name': test_rule_name,
        'direction': 'out',
        'action': 'block',
        'protocol': 'TCP',
        'local_port': '9090',
        'description': 'Temporary test rule',
        'enabled': True
    }
    
    # Test adding the rule
    print("\n[TEST] Adding firewall rule...")
    success = add_rule(test_rule)
    
    if success:
        print(f"[SUCCESS] Rule '{test_rule_name}' added successfully")
    else:
        print(f"[FAIL] Failed to add rule '{test_rule_name}'")
        return False
    
    # Verify rule exists
    if rule_exists(test_rule_name):
        print("[SUCCESS] Rule verified in firewall")
    else:
        print("[FAIL] Rule was supposedly added but doesn't exist in firewall")
        return False
    
    print("\n=== ADD RULE TEST COMPLETED SUCCESSFULLY ===")
    return True

if __name__ == "__main__":
    success = test_add_rule()
    sys.exit(0 if success else 1)
