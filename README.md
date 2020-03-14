# CodeCaveMemory
Example of saving data acquired in the runtime to the program binary

# Requirements

* Windows OS
* Python 3 installed
* pyinstaller (for generating new EXE file)

# Generate new EXE

```
pyinstaller --onefile code_cave_memory.py
```

# Example code

```
CCM = CodeCaveMemory()

print("{} bytes available in the CodeCaveMemory!".format(CCM.available_memory))
print("Data saved in the binary:", CCM.data)

user_message = input("Enter message: ")
if len(user_message) != 0:
    CCM.write_data({"message": user_message})

# Always save current binary at the end
save_exe_data(CCM.exe_path, CCM.exe_data)
```
