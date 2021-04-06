import sys
from Registry import Registry

reg = Registry.Registry(sys.argv[1])

try:
    key = reg.open("Microsoft\\Windows NT\\CurrentVersion")
except Registry.RegistryKeyNotFoundException:
    print("Couldn't find CurrentVersion key. Exiting...")
    sys.exit(1)

for key_value in key.values():
    if key_value.name() == "ProductName":
        if "Windows" in key_value.value():
            print(key_value.value())
            sys.exit(0)

sys.exit(1)