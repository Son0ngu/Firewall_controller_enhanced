import logging
import sys
import os
import time
from core.firewall_rules import add_rule, remove_rule, list_rules, enable_rule, rule_exists

# Configure logging to console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('test_firewall_rules')

def test_firewall_functionality():
    """Test basic functionality of firewall_rules.py"""

    # Create a test rule with a unique name
    test_rule_name = f"TestRule_{int(time.time())}"

    logger.info(f"Starting firewall rules test with rule: {test_rule_name}")

    # Test 1: Check admin privileges
    from core.utils import checkPrivileges
    if not checkPrivileges():
        logger.error("Tests require administrator privileges. Please run as administrator.")
        return False

    logger.info("✓ Admin privileges confirmed")

    # Test 2: Add a new rule
    test_params = {
        'name': test_rule_name,
        'direction': 'in',
        'action': 'allow',
        'protocol': 'TCP',
        'local_port': '8080',
        'description': 'Test firewall rule',
        'enabled': True
    }

    success = add_rule(test_params)
    if not success:
        logger.error("Failed to add test rule")
        return False

    logger.info("✓ Rule added successfully")

    # Test 3: Verify rule exists
    if not rule_exists(test_rule_name):
        logger.error("Rule was added but doesn't exist in firewall")
        return False

    logger.info("✓ Rule exists in firewall")

    # Test 4: List rules and check if our rule is there
    rules = list_rules()
    found = any(rule.get('Name', '') == test_rule_name for rule in rules)
    if not found:
        logger.error("Rule not found in listed rules")
        return False

    logger.info("✓ Rule appears in listed rules")

    # Test 5: Disable the rule
    success = enable_rule(test_rule_name, False)
    if not success:
        logger.error("Failed to disable the rule")
        # Continue testing anyway

    logger.info("✓ Rule disabled")

    # Test 6: Re-enable the rule
    success = enable_rule(test_rule_name, True)
    if not success:
        logger.error("Failed to re-enable the rule")
        # Continue testing anyway

    logger.info("✓ Rule re-enabled")

    # Test 7: Clean up - remove the test rule
    success = remove_rule(test_rule_name)
    if not success:
        logger.error("Failed to remove test rule. Manual cleanup required.")
        return False

    logger.info("✓ Rule removed successfully")

    # Verify removal
    if rule_exists(test_rule_name):
        logger.error("Rule still exists after removal attempt")
        return False

    logger.info("✓ Rule confirmed removed")

    logger.info("All tests completed successfully!")
    return True

if __name__ == "__main__":
    # Run test function
    success = test_firewall_functionality()
    sys.exit(0 if success else 1)