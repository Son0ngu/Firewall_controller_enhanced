import os
import csv

def compare_rules(primary_rule: str, secondary_rules: list):
    result = []
    for rule in secondary_rules:
        if str(primary_rule).strip() == str(rule).strip():
            result.append(True)
        else:
            result.append(False)
        
    return any(result)

def validate_with_route_table(src_addr, dst_addr, src_port, dst_port):
    try:
        with open("./imports/Rules.csv", "r") as rules_stream:
            rules = csv.reader(rules_stream)

            for rule in rules:
                # <SRC_IP> <SRC_PORT> <DST_IP> <DST_PORT>
                # check for IP
                if compare_rules(rule[1], [src_addr, dst_addr, "any"]) and compare_rules(rule[3], [dst_addr, src_addr, "any"]):
                    # check for port
                    if compare_rules(rule[2], [src_port, "any", 0]) and compare_rules(rule[4], [dst_port, "any", 0]):
                        if str(rule[0]).lower() == "allow":
                            return True
                        elif str(rule[0]).lower() == "deny" or str(rule[0]).lower() == "disable":
                            continue
            return False  # Properly indented outside the loop
    except Exception as e:
        print(f"[ERR] Error reading rules: {e}")
        return False

# Uncomment these lines if you want to test the function
# print(validate_with_route_table("0.0.0.0", "127.0.0.0", 22, 22))
# print(validate_with_route_table("192.168.2.100", "192.168.1.100", 22, 0))
# print(validate_with_route_table("192.168.2.100", "100", 80, 90))