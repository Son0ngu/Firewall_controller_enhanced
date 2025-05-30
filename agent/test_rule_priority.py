# filepath: c:\Users\sonbx\firewall-controller\agent\test_firewall_advanced.py
"""
Advanced Firewall Manager Test Suite
Comprehensive testing with edge cases, stress tests, and advanced scenarios
"""

import logging
import subprocess
import time
import sys
import os
import threading
import random
import socket
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Set, Optional
import concurrent.futures
import psutil

# Add current directory to path to import firewall_manager
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from firewall_manager import FirewallManager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger("test_firewall_advanced")

class AdvancedFirewallTester:
    """Advanced test class for comprehensive firewall testing"""
    
    def __init__(self):
        self.firewall = FirewallManager("TestAdvanced")
        self.test_results = {}
        self.performance_metrics = {}
        self.stress_test_results = {}
        
    def run_all_tests(self):
        """Run advanced test suite"""
        print("🚀 ADVANCED FIREWALL TESTING SUITE")
        print("=" * 80)
        
        try:
            # Cleanup first
            self.cleanup_test_rules()
            
            # Basic functionality edge cases
            self.test_ip_validation_comprehensive()
            self.test_rule_naming_edge_cases()
            self.test_prefix_variations()
            
            # Performance and scalability tests
            self.test_massive_ruleset_creation()
            self.test_rapid_fire_operations()
            self.test_memory_usage_monitoring()
            
            # Concurrency and race condition tests
            self.test_concurrent_whitelist_changes()
            self.test_race_condition_scenarios()
            self.test_simultaneous_cleanup_operations()
            
            # Network and connectivity tests
            self.test_network_interface_awareness()
            self.test_dns_resolution_handling()
            self.test_local_network_detection()
            
            # Error handling and recovery tests
            self.test_system_resource_exhaustion()
            self.test_permission_edge_cases()
            self.test_corrupted_state_recovery()
            
            # Integration and lifecycle tests
            self.test_long_running_operations()
            self.test_system_reboot_simulation()
            self.test_cross_session_persistence()
            
            # Security and validation tests
            self.test_malicious_input_handling()
            self.test_rule_injection_prevention()
            self.test_privilege_escalation_prevention()
            
            # Performance benchmarking
            self.test_comprehensive_performance_suite()
            
            # Final cleanup
            self.cleanup_test_rules()
            
            # Print comprehensive summary
            self.print_advanced_summary()
            
        except Exception as e:
            logger.error(f"Advanced test suite failed: {e}")
            print(f"❌ Advanced test suite failed: {e}")

    def test_ip_validation_comprehensive(self):
        """Test 1: Comprehensive IP validation with edge cases"""
        print("\n1. 🔍 TESTING COMPREHENSIVE IP VALIDATION")
        print("-" * 50)
        
        # Extended edge cases
        test_cases = {
            # Border cases
            "0.0.0.1": True,
            "0.0.1.0": True,
            "0.1.0.0": True,
            "1.0.0.0": True,
            "255.255.255.254": True,
            "255.255.254.255": True,
            "255.254.255.255": True,
            "254.255.255.255": True,
            
            # Network addresses
            "10.0.0.0": True,
            "172.16.0.0": True,
            "192.168.0.0": True,
            "224.0.0.0": True,  # Multicast start
            "239.255.255.255": True,  # Multicast end
            
            # Special addresses
            "169.254.1.1": True,  # Link-local
            "127.0.0.2": True,    # Loopback range
            "0.0.0.0": True,      # Any address
            "255.255.255.255": True,  # Broadcast
            
            # Unicode and international
            "１２７.０.０.１": False,  # Full-width numbers
            "127.0.0.①": False,      # Unicode numbers
            "127.0.0.1 ": False,     # Trailing space
            " 127.0.0.1": False,     # Leading space
            "127.0.0.1\t": False,    # Tab character
            "127.0.0.1\n": False,    # Newline
            
            # Scientific notation
            "1e2.0.0.1": False,
            "127.0.0.1e0": False,
            "1.27e2.0.1": False,
            
            # Hexadecimal
            "0x7F.0.0.1": False,
            "127.0x0.0.1": False,
            "127.0.0.0x1": False,
            
            # Octal (leading zeros should be handled)
            "0127.0.0.1": True,   # Should be treated as 127
            "127.000.000.001": True,
            "008.008.008.008": True,  # Should be 8.8.8.8
            
            # Binary
            "0b1111111.0.0.1": False,
            "127.0b0.0.1": False,
            
            # Very long inputs
            "127.0.0." + "1" * 100: False,
            "127.0.0.1" + "." + "1" * 100: False,
            "1" * 100 + ".0.0.1": False,
            
            # SQL injection attempts
            "127.0.0.1'; DROP TABLE --": False,
            "127.0.0.1 OR 1=1": False,
            "127.0.0.1 UNION SELECT": False,
            
            # Path traversal attempts
            "../127.0.0.1": False,
            "127.0.0.1/../": False,
            "..\\127.0.0.1": False,
            
            # Special characters
            "127.0.0.1@": False,
            "127.0.0.1#": False,
            "127.0.0.1$": False,
            "127.0.0.1%": False,
            "127.0.0.1&": False,
            "127.0.0.1*": False,
            "127.0.0.1!": False,
            
            # URL-like formats
            "http://127.0.0.1": False,
            "127.0.0.1:8080": False,
            "127.0.0.1/path": False,
            "user@127.0.0.1": False,
            
            # Multiple dots
            "127..0.0.1": False,
            "127.0..0.1": False,
            "127.0.0..1": False,
            "...127.0.0.1": False,
            "127.0.0.1...": False,
            
            # Empty segments
            ".0.0.1": False,
            "127..0.1": False,
            "127.0.0.": False,
            ".": False,
            "..": False,
            "...": False,
        }
        
        validation_results = {}
        passed_count = 0
        
        for ip, expected in test_cases.items():
            try:
                result = self.firewall._is_valid_ipv4(ip)
                if result == expected:
                    validation_results[ip] = "✅ CORRECT"
                    passed_count += 1
                    if len(ip) <= 30:
                        print(f"   ✅ '{ip}' -> {result}: CORRECT")
                    else:
                        print(f"   ✅ '{ip[:27]}...' -> {result}: CORRECT")
                else:
                    validation_results[ip] = f"❌ WRONG: got {result}, expected {expected}"
                    if len(ip) <= 30:
                        print(f"   ❌ '{ip}' -> {result} (expected {expected}): WRONG")
                    else:
                        print(f"   ❌ '{ip[:27]}...' -> {result} (expected {expected}): WRONG")
            except Exception as e:
                validation_results[ip] = f"❌ ERROR: {e}"
                print(f"   ❌ '{ip[:30]}...': ERROR - {str(e)[:50]}...")
        
        total_count = len(validation_results)
        pass_rate = passed_count / total_count * 100
        
        print(f"\n   📊 IP Validation Results:")
        print(f"      Total cases: {total_count}")
        print(f"      Passed: {passed_count} ({pass_rate:.1f}%)")
        print(f"      Failed: {total_count - passed_count}")
        
        if pass_rate >= 95:
            self.test_results["ip_validation_comprehensive"] = "✅ EXCELLENT"
            print("   🎉 IP validation: EXCELLENT")
        elif pass_rate >= 85:
            self.test_results["ip_validation_comprehensive"] = "✅ GOOD"
            print("   ✅ IP validation: GOOD")
        elif pass_rate >= 70:
            self.test_results["ip_validation_comprehensive"] = "⚠️ ACCEPTABLE"
            print("   ⚠️ IP validation: ACCEPTABLE")
        else:
            self.test_results["ip_validation_comprehensive"] = "❌ POOR"
            print("   ❌ IP validation: NEEDS IMPROVEMENT")

    def test_rule_naming_edge_cases(self):
        """Test 2: Rule naming with various edge cases"""
        print("\n2. 📝 TESTING RULE NAMING EDGE CASES")
        print("-" * 50)
        
        try:
            naming_tests = {}
            
            # Test very long rule names
            long_ip = "192.168.1.100"
            very_long_reason = "A" * 200  # Very long reason
            
            result1 = self.firewall._create_allow_rule_with_priority(long_ip, very_long_reason)
            naming_tests["very_long_reason"] = "✅ SUCCESS" if result1 else "❌ FAILED"
            print(f"   Very long reason: {'✅ SUCCESS' if result1 else '❌ FAILED'}")
            
            # Test special characters in reason
            special_chars_reason = "test-rule_with#special@chars!"
            result2 = self.firewall._create_allow_rule_with_priority("192.168.1.101", special_chars_reason)
            naming_tests["special_chars"] = "✅ SUCCESS" if result2 else "❌ FAILED"
            print(f"   Special characters: {'✅ SUCCESS' if result2 else '❌ FAILED'}")
            
            # Test unicode in reason
            unicode_reason = "测试规则_тест_テスト"
            result3 = self.firewall._create_allow_rule_with_priority("192.168.1.102", unicode_reason)
            naming_tests["unicode"] = "✅ SUCCESS" if result3 else "❌ FAILED"
            print(f"   Unicode characters: {'✅ SUCCESS' if result3 else '❌ FAILED'}")
            
            # Test empty reason
            result4 = self.firewall._create_allow_rule_with_priority("192.168.1.103", "")
                
                results1 = future1.result()
                results2 = future2.result()
                results3 = future3.result()
            
            concurrent_time = time.time() - start_time
            
            all_results = results1 + results2 + results3
            success_count = sum(1 for _, success in all_results if success)
            total_count = len(all_results)
            
            print(f"   Concurrent rule creation: {concurrent_time:.3f}s")
            print(f"   Success rate: {success_count}/{total_count} ({success_count/total_count*100:.1f}%)")
            
            # Verify no rule conflicts
            rule_order_ok = self.verify_rule_order()
            print(f"   Rule order maintained: {'✅ YES' if rule_order_ok else '❌ NO'}")
            
            concurrent_ok = (success_count/total_count >= 0.8 and rule_order_ok)
            
            if concurrent_ok:
                self.test_results["concurrent_operations"] = "✅ PASS"
                print("   🎉 Concurrent operations: SUCCESS")
            else:
                self.test_results["concurrent_operations"] = "❌ FAIL"
                print("   ❌ Concurrent operations: FAILED")
                
        except Exception as e:
            self.test_results["concurrent_operations"] = f"❌ ERROR: {e}"
            print(f"   ❌ Test failed: {e}")

    def test_priority_ordering_stress(self):
        """Test 5: Priority ordering under stress"""
        print("\n5. 💪 TESTING PRIORITY ORDERING STRESS")
        print("-" * 50)
        
        try:
            # Clean up first
            self.cleanup_test_rules()
            time.sleep(2)
            
            # Create rules in random order with delays
            test_ips = [f"10.0.{i//255}.{i%255}" for i in range(1, 21)]  # 20 IPs
            random.shuffle(test_ips)  # Random order
            
            print(f"   Creating {len(test_ips)} rules in random order...")
            
            created_count = 0
            for i, ip in enumerate(test_ips):
                # Random small delay to simulate real-world timing
                time.sleep(random.uniform(0.01, 0.05))
                
                success = self.firewall._create_allow_rule_with_priority(ip, f"stress_{i}")
                if success:
                    created_count += 1
                
                if (i + 1) % 5 == 0:
                    print(f"   Progress: {i+1}/{len(test_ips)} rules created")
            
            print(f"   Created {created_count}/{len(test_ips)} rules")
            
            # Create default block rule
            time.sleep(0.1)
            block_success = self.firewall._create_default_block_rule_with_priority()
            print(f"   Default block rule: {'✅ SUCCESS' if block_success else '❌ FAILED'}")
            
            # Verify order multiple times
            order_checks = []
            for check in range(3):
                time.sleep(0.5)
                order_ok = self.verify_rule_order()
                order_checks.append(order_ok)
                print(f"   Order check {check+1}: {'✅ PASS' if order_ok else '❌ FAIL'}")
            
            stress_success = (
                created_count == len(test_ips) and
                block_success and
                all(order_checks)
            )
            
            if stress_success:
                self.test_results["priority_ordering_stress"] = "✅ PASS"
                print("   🎉 Priority ordering stress: SUCCESS")
            else:
                self.test_results["priority_ordering_stress"] = "❌ FAIL"
                print("   ❌ Priority ordering stress: FAILED")
                
        except Exception as e:
            self.test_results["priority_ordering_stress"] = f"❌ ERROR: {e}"
            print(f"   ❌ Test failed: {e}")

    def test_large_whitelist_setup(self):
        """Test 6: Large whitelist setup"""
        print("\n6. 📊 TESTING LARGE WHITELIST SETUP")
        print("-" * 50)
        
        try:
            # Clean up first
            self.cleanup_test_rules()
            time.sleep(2)
            
            # Generate large IP set (50 IPs)
            large_ip_set = set()
            for i in range(1, 51):
                large_ip_set.add(f"172.16.{i//255}.{i%255}")
            
            print(f"   Setting up whitelist with {len(large_ip_set)} IPs...")
            
            # Measure setup time
            start_time = time.time()
            setup_success = self.firewall.setup_whitelist_firewall(large_ip_set)
            setup_time = time.time() - start_time
            
            print(f"   Setup result: {'✅ SUCCESS' if setup_success else '❌ FAILED'}")
            print(f"   Setup time: {setup_time:.2f} seconds")
            print(f"   Average per IP: {setup_time/len(large_ip_set):.3f} seconds")
            
            if setup_success:
                # Verify whitelist status
                status = self.firewall.get_whitelist_status()
                print(f"   Whitelist active: {status.get('whitelist_mode_active', False)}")
                print(f"   Allowed IPs count: {status.get('allowed_ips_count', 0)}")
                print(f"   Default block created: {status.get('default_block_created', False)}")
                
                # Verify rule order
                order_ok = self.verify_rule_order()
                print(f"   Rule order correct: {'✅ YES' if order_ok else '❌ NO'}")
                
                # Performance check (should complete within reasonable time)
                performance_ok = setup_time < 120  # 2 minutes max
                
                large_whitelist_ok = (
                    setup_success and
                    status.get('whitelist_mode_active', False) and
                    status.get('allowed_ips_count', 0) >= len(large_ip_set) and
                    order_ok and
                    performance_ok
                )
                
                if large_whitelist_ok:
                    self.test_results["large_whitelist_setup"] = "✅ PASS"
                    print("   🎉 Large whitelist setup: SUCCESS")
                else:
                    self.test_results["large_whitelist_setup"] = "⚠️ PARTIAL"
                    print("   ⚠️ Large whitelist setup: PARTIAL SUCCESS")
            else:
                self.test_results["large_whitelist_setup"] = "❌ FAIL"
                print("   ❌ Large whitelist setup: FAILED")
                
        except Exception as e:
            self.test_results["large_whitelist_setup"] = f"❌ ERROR: {e}"
            print(f"   ❌ Test failed: {e}")

    def test_error_handling(self):
        """Test 7: Error handling scenarios"""
        print("\n7. 🛡️ TESTING ERROR HANDLING")
        print("-" * 50)
        
        error_tests = {}
        
        try:
            # Test 1: Invalid IP handling
            try:
                result = self.firewall._create_allow_rule_with_priority("invalid.ip", "test")
                error_tests["invalid_ip"] = "❌ Should have failed" if result else "✅ Correctly rejected"
            except Exception:
                error_tests["invalid_ip"] = "✅ Exception handled"
            
            # Test 2: Empty IP handling
            try:
                result = self.firewall._create_allow_rule_with_priority("", "test")
                error_tests["empty_ip"] = "❌ Should have failed" if result else "✅ Correctly rejected"
            except Exception:
                error_tests["empty_ip"] = "✅ Exception handled"
            
            # Test 3: None IP handling
            try:
                result = self.firewall._create_allow_rule_with_priority(None, "test")
                error_tests["none_ip"] = "❌ Should have failed" if result else "✅ Correctly rejected"
            except Exception:
                error_tests["none_ip"] = "✅ Exception handled"
            
            # Test 4: Duplicate IP handling
            test_ip = "192.168.200.1"
            self.firewall._create_allow_rule_with_priority(test_ip, "test1")
            try:
                result = self.firewall._create_allow_rule_with_priority(test_ip, "test2")
                error_tests["duplicate_ip"] = "⚠️ Allowed duplicate" if result else "✅ Rejected duplicate"
            except Exception:
                error_tests["duplicate_ip"] = "✅ Exception on duplicate"
            
            # Test 5: Invalid reason handling
            try:
                result = self.firewall._create_allow_rule_with_priority("192.168.200.2", "")
                error_tests["empty_reason"] = "✅ Handled empty reason" if result else "⚠️ Rejected empty reason"
            except Exception:
                error_tests["empty_reason"] = "✅ Exception on empty reason"
            
            # Print results
            for test_name, result in error_tests.items():
                print(f"   {result.split()[0]} {test_name.replace('_', ' ').title()}: {result}")
            
            # Overall assessment
            good_results = sum(1 for r in error_tests.values() if r.startswith("✅"))
            total_results = len(error_tests)
            
            if good_results >= total_results * 0.8:  # 80% threshold
                self.test_results["error_handling"] = "✅ PASS"
                print(f"   🎉 Error handling: {good_results}/{total_results} GOOD")
            else:
                self.test_results["error_handling"] = f"⚠️ PARTIAL: {good_results}/{total_results}"
                print(f"   ⚠️ Error handling: {good_results}/{total_results} GOOD")
                
        except Exception as e:
            self.test_results["error_handling"] = f"❌ ERROR: {e}"
            print(f"   ❌ Test failed: {e}")

    def test_full_lifecycle(self):
        """Test 8: Full lifecycle operations"""
        print("\n8. 🔄 TESTING FULL LIFECYCLE")
        print("-" * 50)
        
        try:
            # Clean start
            self.cleanup_test_rules()
            time.sleep(2)
            
            lifecycle_steps = {}
            
            # Step 1: Initial setup
            initial_ips = {"192.168.50.1", "192.168.50.2", "192.168.50.3"}
            setup_success = self.firewall.setup_whitelist_firewall(initial_ips)
            lifecycle_steps["initial_setup"] = "✅ SUCCESS" if setup_success else "❌ FAILED"
            print(f"   Initial setup: {'✅ SUCCESS' if setup_success else '❌ FAILED'}")
            
            # Step 2: Add IPs
            add_ips = {"192.168.50.4", "192.168.50.5"}
            current_ips = self.firewall.allowed_ips.copy()
            sync_success = self.firewall.sync_whitelist_changes(current_ips, current_ips | add_ips)
            lifecycle_steps["add_ips"] = "✅ SUCCESS" if sync_success else "❌ FAILED"
            print(f"   Add IPs: {'✅ SUCCESS' if sync_success else '❌ FAILED'}")
            
            # Step 3: Remove IPs
            remove_ips = {"192.168.50.1"}
            current_ips = self.firewall.allowed_ips.copy()
            sync_success = self.firewall.sync_whitelist_changes(current_ips, current_ips - remove_ips)
            lifecycle_steps["remove_ips"] = "✅ SUCCESS" if sync_success else "❌ FAILED"
            print(f"   Remove IPs: {'✅ SUCCESS' if sync_success else '❌ FAILED'}")
            
            # Step 4: Verify state
            status = self.firewall.get_whitelist_status()
            expected_count = len(initial_ips) + len(add_ips) - len(remove_ips)
            actual_count = status.get('allowed_ips_count', 0)
            state_ok = (actual_count >= expected_count)  # Allow for essential IPs
            lifecycle_steps["verify_state"] = "✅ SUCCESS" if state_ok else "❌ FAILED"
            print(f"   State verification: {'✅ SUCCESS' if state_ok else '❌ FAILED'}")
            print(f"     Expected ≥{expected_count}, got {actual_count}")
            
            # Step 5: Rule order check
            order_ok = self.verify_rule_order()
            lifecycle_steps["rule_order"] = "✅ SUCCESS" if order_ok else "❌ FAILED"
            print(f"   Rule order: {'✅ SUCCESS' if order_ok else '❌ FAILED'}")
            
            # Step 6: Final cleanup
            cleanup_success = self.firewall.cleanup_all_rules()
            lifecycle_steps["cleanup"] = "✅ SUCCESS" if cleanup_success else "❌ FAILED"
            print(f"   Cleanup: {'✅ SUCCESS' if cleanup_success else '❌ FAILED'}")
            
            # Overall assessment
            success_count = sum(1 for r in lifecycle_steps.values() if r.startswith("✅"))
            total_count = len(lifecycle_steps)
            
            if success_count == total_count:
                self.test_results["full_lifecycle"] = "✅ PASS"
                print(f"   🎉 Full lifecycle: ALL {total_count} STEPS PASSED")
            else:
                self.test_results["full_lifecycle"] = f"⚠️ PARTIAL: {success_count}/{total_count}"
                print(f"   ⚠️ Full lifecycle: {success_count}/{total_count} STEPS PASSED")
                
        except Exception as e:
            self.test_results["full_lifecycle"] = f"❌ ERROR: {e}"
            print(f"   ❌ Test failed: {e}")

    def test_performance_benchmarks(self):
        """Test 9: Performance benchmarks"""
        print("\n9. 📈 TESTING PERFORMANCE BENCHMARKS")
        print("-" * 50)
        
        try:
            benchmarks = {}
            
            # Benchmark 1: Rule listing speed
            start_time = time.time()
            rules = self.get_our_rules()
            list_time = time.time() - start_time
            benchmarks["rule_listing"] = list_time
            print(f"   Rule listing: {list_time:.3f}s for {len(rules)} rules")
            
            # Benchmark 2: Status check speed
            start_time = time.time()
            status = self.firewall.get_whitelist_status()
            status_time = time.time() - start_time
            benchmarks["status_check"] = status_time
            print(f"   Status check: {status_time:.3f}s")
            
            # Benchmark 3: Validation speed
            if hasattr(self.firewall, 'validate_firewall_state'):
                start_time = time.time()
                validation = self.firewall.validate_firewall_state()
                validation_time = time.time() - start_time
                benchmarks["validation"] = validation_time
                print(f"   State validation: {validation_time:.3f}s")
            
            # Performance assessment
            thresholds = {
                "rule_listing": 5.0,    # 5 seconds max
                "status_check": 2.0,    # 2 seconds max
                "validation": 10.0      # 10 seconds max
            }
            
            performance_ok = all(
                benchmarks.get(metric, 0) <= threshold 
                for metric, threshold in thresholds.items()
            )
            
            self.performance_metrics.update(benchmarks)
            
            if performance_ok:
                self.test_results["performance_benchmarks"] = "✅ PASS"
                print("   🎉 Performance benchmarks: ALL WITHIN LIMITS")
            else:
                self.test_results["performance_benchmarks"] = "⚠️ SLOW"
                print("   ⚠️ Performance benchmarks: SOME EXCEEDED LIMITS")
                
        except Exception as e:
            self.test_results["performance_benchmarks"] = f"❌ ERROR: {e}"
            print(f"   ❌ Test failed: {e}")

    # Helper methods
    def verify_rule_order(self) -> bool:
        """Verify that ALLOW rules come before BLOCK rules"""
        try:
            rules = self.get_our_rules()
            if not rules:
                return True
            
            # Sort rules alphabetically
            sorted_rules = sorted(rules)
            
            # Find ALLOW and BLOCK rule positions
            allow_positions = [i for i, rule in enumerate(sorted_rules) if "_Allow_" in rule]
            block_positions = [i for i, rule in enumerate(sorted_rules) if "_DefaultBlock_" in rule]
            
            if not allow_positions or not block_positions:
                return True  # No conflicts if only one type exists
            
            # Check if all ALLOW rules come before all BLOCK rules
            max_allow_pos = max(allow_positions)
            min_block_pos = min(block_positions)
            
            return max_allow_pos < min_block_pos
            
        except Exception as e:
            logger.error(f"Error verifying rule order: {e}")
            return False

    def get_our_rules(self) -> List[str]:
        """Get list of our firewall rule names"""
        try:
            command = [
                "netsh", "advfirewall", "firewall", "show", "rule",
                "name=all"
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode != 0:
                return []
            
            rules = []
            for line in result.stdout.split('\n'):
                if line.strip().startswith("Rule Name:"):
                    rule_name = line.strip()[10:].strip()
                    if rule_name.startswith(self.firewall.rule_prefix):
                        rules.append(rule_name)
            
            return rules
            
        except Exception as e:
            logger.error(f"Error getting rules: {e}")
            return []

    def cleanup_test_rules(self):
        """Clean up all test rules"""
        try:
            print("   🧹 Cleaning up test rules...")
            success = self.firewall.cleanup_all_rules()
            print(f"   Cleanup: {'✅ SUCCESS' if success else '❌ FAILED'}")
            time.sleep(1)
        except Exception as e:
            print(f"   ❌ Cleanup failed: {e}")

    def print_comprehensive_summary(self):
        """Print comprehensive test summary with performance metrics"""
        print("\n" + "=" * 70)
        print("🏁 COMPREHENSIVE TEST SUMMARY")
        print("=" * 70)
        
        # Test results summary
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results.values() if r.startswith("✅")])
        failed_tests = len([r for r in self.test_results.values() if r.startswith("❌")])
        partial_tests = len([r for r in self.test_results.values() if r.startswith("⚠️")])
        
        print("\n📊 TEST RESULTS:")
        for test_name, result in self.test_results.items():
            status_icon = result.split()[0]
            test_display = test_name.replace('_', ' ').title()
            print(f"   {status_icon} {test_display}")
            if not result.startswith("✅"):
                print(f"      └─ {result}")
        
        # Performance metrics summary
        if self.performance_metrics:
            print("\n⚡ PERFORMANCE METRICS:")
            for metric, value in self.performance_metrics.items():
                metric_display = metric.replace('_', ' ').title()
                if isinstance(value, float):
                    print(f"   📈 {metric_display}: {value:.3f}s")
                else:
                    print(f"   📈 {metric_display}: {value}")
        
        # Overall summary
        print(f"\n📈 SUMMARY STATISTICS:")
        print(f"   Total Tests: {total_tests}")
        print(f"   Passed: {passed_tests} ({passed_tests/total_tests*100:.1f}%)")
        print(f"   Partial: {partial_tests} ({partial_tests/total_tests*100:.1f}%)")
        print(f"   Failed: {failed_tests} ({failed_tests/total_tests*100:.1f}%)")
        
        # Final assessment
        if failed_tests == 0 and partial_tests == 0:
            print(f"\n🎉 EXCELLENT! All tests passed with full functionality.")
        elif failed_tests == 0:
            print(f"\n✅ GOOD! All tests passed but some performance issues noted.")
        elif passed_tests >= failed_tests:
            print(f"\n⚠️ ACCEPTABLE! Most functionality works but needs attention.")
        else:
            print(f"\n❌ NEEDS WORK! Significant issues found requiring fixes.")
        
        print("=" * 70)

def main():
    """Main test execution"""
    print("🚀 Starting Comprehensive Firewall Tests...")
    print(f"📅 Test started at: {datetime.now()}")
    
    # Check admin privileges
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "currentprofile"],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode != 0:
            print("❌ Administrator privileges required!")
            print("   Please run this test as Administrator.")
            return
        else:
            print("✅ Administrator privileges detected.")
    except Exception as e:
        print(f"❌ Could not check admin privileges: {e}")
        return
    
    # Run comprehensive tests
    tester = ComprehensiveFirewallTester()
    tester.run_all_tests()
    
    print(f"\n📅 Test completed at: {datetime.now()}")

if __name__ == "__main__":
    main()

logger = logging.getLogger("test_rule_priority")

class RulePriorityTester:
    """Test class for verifying firewall rule priority ordering"""
    
    def __init__(self):
        self.firewall = FirewallManager("TestPriority")
        self.test_results = {}
        
    def run_all_tests(self):
        """Run comprehensive rule priority tests"""
        print("🧪 FIREWALL RULE PRIORITY TESTING SUITE")
        print("=" * 60)
        
        try:
            # Cleanup any existing test rules first
            self.cleanup_test_rules()
            
            # Test 1: Basic rule creation order
            self.test_basic_rule_creation_order()
            
            # Test 2: Alphabetical ordering verification
            self.test_alphabetical_ordering()
            
            # Test 3: Rule parsing and verification
            self.test_rule_parsing()
            
            # Test 4: Whitelist setup with priority
            self.test_whitelist_setup_priority()
            
            # Test 5: Rule order after multiple operations
            self.test_multiple_operations_order()
            
            # Test 6: Rule order verification methods
            self.test_rule_verification_methods()
            
            # Final cleanup
            self.cleanup_test_rules()
            
            # Print summary
            self.print_test_summary()
            
        except Exception as e:
            logger.error(f"Test suite failed: {e}")
            print(f"❌ Test suite failed: {e}")

    def test_basic_rule_creation_order(self):
        """Test 1: Basic rule creation order"""
        print("\n1. 🔧 TESTING BASIC RULE CREATION ORDER")
        print("-" * 50)
        
        try:
            # Create some allow rules first
            test_ips = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
            
            print(f"   Creating ALLOW rules for: {test_ips}")
            for ip in test_ips:
                success = self.firewall._create_allow_rule_with_priority(ip, "test")
                print(f"   {'✅' if success else '❌'} Allow rule for {ip}: {'SUCCESS' if success else 'FAILED'}")
            
            time.sleep(1)  # Ensure different timestamps
            
            # Create default block rule
            print(f"   Creating DEFAULT BLOCK rule...")
            block_success = self.firewall._create_default_block_rule_with_priority()
            print(f"   {'✅' if block_success else '❌'} Block rule: {'SUCCESS' if block_success else 'FAILED'}")
            
            # Verify order
            order_correct = self.verify_rule_order_detailed()
            
            if order_correct:
                self.test_results["basic_creation_order"] = "✅ PASS"
                print("   🎉 Basic rule creation order: CORRECT")
            else:
                self.test_results["basic_creation_order"] = "❌ FAIL"
                print("   ❌ Basic rule creation order: INCORRECT")
                
        except Exception as e:
            self.test_results["basic_creation_order"] = f"❌ ERROR: {e}"
            print(f"   ❌ Test failed: {e}")

    def test_alphabetical_ordering(self):
        """Test 2: Verify alphabetical ordering strategy"""
        print("\n2. 🔤 TESTING ALPHABETICAL ORDERING STRATEGY")
        print("-" * 50)
        
        try:
            rules = self.get_our_rules_detailed()
            
            allow_rules = [r for r in rules if r['action'] == 'allow']
            block_rules = [r for r in rules if r['action'] == 'block']
            
            print(f"   Found {len(allow_rules)} ALLOW rules and {len(block_rules)} BLOCK rules")
            
            if not allow_rules and not block_rules:
                print("   ⚠️ No rules found for testing")
                self.test_results["alphabetical_ordering"] = "⚠️ SKIP: No rules"
                return
            
            # Check naming patterns
            alphabetical_correct = True
            
            # Verify ALLOW rules have 'A' prefix
            for rule in allow_rules:
                if "_Allow_A" not in rule['name']:
                    print(f"   ❌ ALLOW rule missing 'A' prefix: {rule['name']}")
                    alphabetical_correct = False
                else:
                    print(f"   ✅ ALLOW rule has correct prefix: {rule['name'][:50]}...")
            
            # Verify BLOCK rules have 'Z' prefix
            for rule in block_rules:
                if "_DefaultBlock_Z" not in rule['name']:
                    print(f"   ❌ BLOCK rule missing 'Z' prefix: {rule['name']}")
                    alphabetical_correct = False
                else:
                    print(f"   ✅ BLOCK rule has correct prefix: {rule['name'][:50]}...")
            
            # Verify alphabetical order
            if allow_rules and block_rules:
                first_allow = min(r['name'] for r in allow_rules)
                last_block = max(r['name'] for r in block_rules)
                
                if first_allow < last_block:
                    print(f"   ✅ Alphabetical order: ALLOW < BLOCK")
                    print(f"      First ALLOW: {first_allow[:60]}...")
                    print(f"      Last BLOCK:  {last_block[:60]}...")
                else:
                    print(f"   ❌ Alphabetical order: ALLOW >= BLOCK")
                    print(f"      First ALLOW: {first_allow[:60]}...")
                    print(f"      Last BLOCK:  {last_block[:60]}...")
                    alphabetical_correct = False
            
            if alphabetical_correct:
                self.test_results["alphabetical_ordering"] = "✅ PASS"
                print("   🎉 Alphabetical ordering: CORRECT")
            else:
                self.test_results["alphabetical_ordering"] = "❌ FAIL"
                print("   ❌ Alphabetical ordering: INCORRECT")
                
        except Exception as e:
            self.test_results["alphabetical_ordering"] = f"❌ ERROR: {e}"
            print(f"   ❌ Test failed: {e}")

    def test_rule_parsing(self):
        """Test 3: Rule parsing and data extraction"""
        print("\n3. 📋 TESTING RULE PARSING")
        print("-" * 50)
        
        try:
            rules = self.get_our_rules_detailed()
            
            if not rules:
                print("   ⚠️ No rules found for parsing test")
                self.test_results["rule_parsing"] = "⚠️ SKIP: No rules"
                return
            
            parsing_success = True
            
            for rule in rules:
                print(f"   📄 Rule: {rule['name'][:50]}...")
                print(f"      Action: {rule['action']}")
                print(f"      Direction: {rule.get('direction', 'N/A')}")
                print(f"      Remote IP: {rule.get('remote_ip', 'N/A')}")
                print(f"      Protocol: {rule.get('protocol', 'N/A')}")
                
                # Verify required fields
                if not rule.get('action'):
                    print(f"      ❌ Missing action")
                    parsing_success = False
                
                if rule['action'] == 'allow' and not rule.get('remote_ip'):
                    print(f"      ❌ ALLOW rule missing remote IP")
                    parsing_success = False
                
                print()
            
            if parsing_success:
                self.test_results["rule_parsing"] = "✅ PASS"
                print("   ✅ Rule parsing: SUCCESS")
            else:
                self.test_results["rule_parsing"] = "❌ FAIL"
                print("   ❌ Rule parsing: FAILED")
                
        except Exception as e:
            self.test_results["rule_parsing"] = f"❌ ERROR: {e}"
            print(f"   ❌ Test failed: {e}")

    def test_whitelist_setup_priority(self):
        """Test 4: Complete whitelist setup with priority verification"""
        print("\n4. 🔄 TESTING COMPLETE WHITELIST SETUP")
        print("-" * 50)
        
        try:
            # Clean up first
            self.cleanup_test_rules()
            time.sleep(2)
            
            # Test IPs
            test_ips = {"8.8.8.8", "1.1.1.1", "192.168.1.1"}
            
            print(f"   Setting up whitelist for: {test_ips}")
            
            # Setup whitelist firewall
            start_time = time.time()
            success = self.firewall.setup_whitelist_firewall(test_ips)
            setup_time = time.time() - start_time
            
            print(f"   Setup result: {'✅ SUCCESS' if success else '❌ FAILED'}")
            print(f"   Setup time: {setup_time:.2f} seconds")
            
            if success:
                # Verify rule order
                time.sleep(1)  # Wait for rules to be fully created
                order_correct = self.verify_rule_order_detailed()
                
                # Check firewall state
                status = self.firewall.get_whitelist_status()
                print(f"   Whitelist mode active: {status['whitelist_mode_active']}")
                print(f"   Default block created: {status['default_block_created']}")
                print(f"   Allowed IPs count: {status['allowed_ips_count']}")
                
                if order_correct and status['whitelist_mode_active']:
                    self.test_results["whitelist_setup"] = "✅ PASS"
                    print("   🎉 Whitelist setup with priority: SUCCESS")
                else:
                    self.test_results["whitelist_setup"] = "❌ PARTIAL"
                    print("   ⚠️ Whitelist setup: PARTIAL SUCCESS")
            else:
                self.test_results["whitelist_setup"] = "❌ FAIL"
                print("   ❌ Whitelist setup: FAILED")
                
        except Exception as e:
            self.test_results["whitelist_setup"] = f"❌ ERROR: {e}"
            print(f"   ❌ Test failed: {e}")

    def test_multiple_operations_order(self):
        """Test 5: Rule order after multiple add/remove operations"""
        print("\n5. 🔄 TESTING MULTIPLE OPERATIONS ORDER")
        print("-" * 50)
        
        try:
            # Add more IPs
            additional_ips = {"208.67.222.222", "9.9.9.9"}
            original_ips = {"8.8.8.8", "1.1.1.1", "192.168.1.1"}
            
            print(f"   Adding additional IPs: {additional_ips}")
            
            for ip in additional_ips:
                success = self.firewall._create_allow_rule_with_priority(ip, "additional")
                print(f"   {'✅' if success else '❌'} Added {ip}: {'SUCCESS' if success else 'FAILED'}")
            
            # Verify order still correct
            order_correct_after_add = self.verify_rule_order_detailed()
            
            # Remove some IPs
            remove_ips = {"1.1.1.1"}
            print(f"   Removing IPs: {remove_ips}")
            
            for ip in remove_ips:
                success = self.firewall._remove_allow_rule(ip)
                print(f"   {'✅' if success else '❌'} Removed {ip}: {'SUCCESS' if success else 'FAILED'}")
            
            # Verify order still correct
            order_correct_after_remove = self.verify_rule_order_detailed()
            
            if order_correct_after_add and order_correct_after_remove:
                self.test_results["multiple_operations"] = "✅ PASS"
                print("   🎉 Multiple operations order: MAINTAINED")
            else:
                self.test_results["multiple_operations"] = "❌ FAIL"
                print("   ❌ Multiple operations order: CORRUPTED")
                
        except Exception as e:
            self.test_results["multiple_operations"] = f"❌ ERROR: {e}"
            print(f"   ❌ Test failed: {e}")

    def test_rule_verification_methods(self):
        """Test 6: Built-in rule verification methods"""
        print("\n6. 🔍 TESTING BUILT-IN VERIFICATION METHODS")
        print("-" * 50)
        
        try:
            # Test _verify_rule_order method
            print("   Testing _verify_rule_order method...")
            sample_ips = list(self.firewall.allowed_ips)[:3] if self.firewall.allowed_ips else []
            
            if sample_ips:
                order_verification = self.firewall._verify_rule_order(sample_ips)
                print(f"   _verify_rule_order: {'✅ PASS' if order_verification else '❌ FAIL'}")
            else:
                print("   _verify_rule_order: ⚠️ SKIP (no IPs)")
                order_verification = True
            
            # Test validate_firewall_state method
            print("   Testing validate_firewall_state method...")
            validation_result = self.firewall.validate_firewall_state()
            
            print(f"   Whitelist mode active: {validation_result.get('whitelist_mode_active', False)}")
            print(f"   Default block created: {validation_result.get('default_block_created', False)}")
            print(f"   Rule order correct: {validation_result.get('rule_order_correct', False)}")
            print(f"   Issues found: {len(validation_result.get('issues', []))}")
            
            if validation_result.get('issues'):
                for issue in validation_result['issues']:
                    print(f"      ⚠️ Issue: {issue}")
            
            # Test connectivity if available
            connectivity_tested = validation_result.get('connectivity_tested', False)
            print(f"   Connectivity tested: {'✅ YES' if connectivity_tested else '❌ NO'}")
            
            if connectivity_tested:
                connectivity_results = validation_result.get('connectivity_results', {})
                success_count = sum(1 for success in connectivity_results.values() if success)
                total_count = len(connectivity_results)
                print(f"   Connectivity success: {success_count}/{total_count}")
            
            # Overall verification assessment
            verification_success = (
                order_verification and 
                validation_result.get('rule_order_correct', False) and
                len(validation_result.get('issues', [])) == 0
            )
            
            if verification_success:
                self.test_results["verification_methods"] = "✅ PASS"
                print("   🎉 Built-in verification methods: ALL PASS")
            else:
                self.test_results["verification_methods"] = "❌ FAIL"
                print("   ❌ Built-in verification methods: SOME FAILED")
                
        except Exception as e:
            self.test_results["verification_methods"] = f"❌ ERROR: {e}"
            print(f"   ❌ Test failed: {e}")

    def verify_rule_order_detailed(self) -> bool:
        """Detailed rule order verification with logging"""
        try:
            print("   🔍 Verifying rule order in detail...")
            
            rules = self.get_our_rules_detailed()
            
            if not rules:
                print("   ⚠️ No rules found")
                return True  # No rules means no order issues
            
            allow_rules = [r for r in rules if r['action'] == 'allow']
            block_rules = [r for r in rules if r['action'] == 'block']
            
            print(f"   📊 Found {len(allow_rules)} ALLOW rules, {len(block_rules)} BLOCK rules")
            
            # Sort rules by name (alphabetical order)
            all_rules_sorted = sorted(rules, key=lambda x: x['name'])
            
            # Check if ALLOW rules come before BLOCK rules
            allow_indices = []
            block_indices = []
            
            for i, rule in enumerate(all_rules_sorted):
                if rule['action'] == 'allow':
                    allow_indices.append(i)
                elif rule['action'] == 'block':
                    block_indices.append(i)
            
            if allow_indices and block_indices:
                max_allow_index = max(allow_indices)
                min_block_index = min(block_indices)
                
                if max_allow_index < min_block_index:
                    print("   ✅ Rule order: ALL ALLOW rules come before ALL BLOCK rules")
                    return True
                else:
                    print("   ❌ Rule order: Some BLOCK rules come before ALLOW rules")
                    print(f"      Max ALLOW index: {max_allow_index}")
                    print(f"      Min BLOCK index: {min_block_index}")
                    
                    # Show problematic rules
                    for i in range(min(max_allow_index, min_block_index), max(max_allow_index, min_block_index) + 1):
                        rule = all_rules_sorted[i]
                        print(f"      [{i}] {rule['action'].upper()}: {rule['name'][:50]}...")
                    
                    return False
            elif allow_rules:
                print("   ✅ Rule order: Only ALLOW rules found (no conflicts)")
                return True
            elif block_rules:
                print("   ⚠️ Rule order: Only BLOCK rules found (unusual but not incorrect)")
                return True
            else:
                print("   ⚠️ Rule order: No rules found")
                return True
                
        except Exception as e:
            print(f"   ❌ Error verifying rule order: {e}")
            return False

    def get_our_rules_detailed(self) -> List[Dict]:
        """Get detailed information about our firewall rules"""
        try:
            command = [
                "netsh", "advfirewall", "firewall", "show", "rule",
                "name=all", "verbose"
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode != 0:
                logger.error("Failed to list rules")
                return []
            
            rules = []
            current_rule = {}
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if line.startswith("Rule Name:"):
                    # Save previous rule if it was ours
                    if current_rule.get('name', '').startswith(self.firewall.rule_prefix):
                        rules.append(current_rule.copy())
                    
                    # Start new rule
                    rule_name = line[10:].strip()
                    current_rule = {'name': rule_name}
                    
                elif current_rule.get('name', '').startswith(self.firewall.rule_prefix):
                    # Parse rule details for our rules only
                    if line.startswith("Action:"):
                        current_rule['action'] = line[7:].strip().lower()
                    elif line.startswith("Direction:"):
                        current_rule['direction'] = line[10:].strip().lower()
                    elif line.startswith("RemoteIP:"):
                        current_rule['remote_ip'] = line[9:].strip()
                    elif line.startswith("Protocol:"):
                        current_rule['protocol'] = line[9:].strip()
                    elif line.startswith("LocalIP:"):
                        current_rule['local_ip'] = line[8:].strip()
                    elif line.startswith("RemotePort:"):
                        current_rule['remote_port'] = line[11:].strip()
                    elif line.startswith("LocalPort:"):
                        current_rule['local_port'] = line[10:].strip()
            
            # Don't forget the last rule
            if current_rule.get('name', '').startswith(self.firewall.rule_prefix):
                rules.append(current_rule)
            
            return rules
            
        except Exception as e:
            logger.error(f"Error getting detailed rules: {e}")
            return []

    def cleanup_test_rules(self):
        """Clean up all test rules"""
        try:
            print("   🧹 Cleaning up test rules...")
            success = self.firewall.cleanup_all_rules()
            print(f"   Cleanup: {'✅ SUCCESS' if success else '❌ FAILED'}")
            time.sleep(1)  # Wait for cleanup to complete
        except Exception as e:
            print(f"   ❌ Cleanup failed: {e}")

    def print_test_summary(self):
        """Print comprehensive test summary"""
        print("\n" + "=" * 60)
        print("🏁 RULE PRIORITY TEST SUMMARY")
        print("=" * 60)
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results.values() if r.startswith("✅")])
        failed_tests = len([r for r in self.test_results.values() if r.startswith("❌")])
        skipped_tests = len([r for r in self.test_results.values() if r.startswith("⚠️")])
        
        for test_name, result in self.test_results.items():
            status_icon = result.split()[0]
            print(f"{status_icon} {test_name.replace('_', ' ').title()}")
            if not result.startswith("✅"):
                print(f"   └─ {result}")
        
        print(f"\n📊 RESULTS SUMMARY:")
        print(f"   Total Tests: {total_tests}")
        print(f"   Passed: {passed_tests} ({passed_tests/total_tests*100:.1f}%)")
        print(f"   Failed: {failed_tests} ({failed_tests/total_tests*100:.1f}%)")
        print(f"   Skipped: {skipped_tests} ({skipped_tests/total_tests*100:.1f}%)")
        
        if failed_tests == 0:
            print(f"\n🎉 ALL TESTS PASSED! Rule priority system is working correctly.")
        elif passed_tests > failed_tests:
            print(f"\n⚠️ MOSTLY SUCCESSFUL but some issues found.")
        else:
            print(f"\n❌ SIGNIFICANT ISSUES found with rule priority system.")
        
        print("=" * 60)

def main():
    """Main test execution"""
    print("🚀 Starting Firewall Rule Priority Tests...")
    print(f"📅 Test started at: {datetime.now()}")
    
    # Check admin privileges
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "currentprofile"],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode != 0:
            print("❌ Administrator privileges required!")
            print("   Please run this test as Administrator.")
            return
        else:
            print("✅ Administrator privileges detected.")
    except Exception as e:
        print(f"❌ Could not check admin privileges: {e}")
        return
    
    # Run tests
    tester = RulePriorityTester()
    tester.run_all_tests()

if __name__ == "__main__":
    main()