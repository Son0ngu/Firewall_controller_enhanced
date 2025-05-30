import ctypes
import platform

def check_admin():
    try:
        if platform.system() == "Windows":
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            print(f"Administrator privileges: {'✅ YES' if is_admin else '❌ NO'}")
            
            if not is_admin:
                print("\n💡 To enable whitelist-only mode:")
                print("   1. Right-click Command Prompt or PowerShell")
                print("   2. Select 'Run as administrator'")
                print("   3. Navigate to: cd C:\\Users\\sonbx\\firewall-controller\\agent")
                print("   4. Run: python agent_main.py")
                print("\n⚠️ Without admin privileges, agent runs in monitor mode only")
            
            return is_admin
        else:
            import os
            is_admin = os.geteuid() == 0
            print(f"Root privileges: {'✅ YES' if is_admin else '❌ NO'}")
            return is_admin
            
    except Exception as e:
        print(f"❌ Error checking privileges: {e}")
        return False

if __name__ == "__main__":
    check_admin()