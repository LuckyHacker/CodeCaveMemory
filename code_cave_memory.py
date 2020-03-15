import os
import pickle
import pefile
import json

from subprocess import Popen


def save_exe_data(path, data):
    # Required to save binary data to the same binary,
    # because new process is needed, and main process must be exited.
    # Always call this function at end of the program.
    with open("tmp.exe", "wb") as f:
        f.write(bytes(data))
    
    with open("tmp.py", "w") as f:
        f.write("import os, time; time.sleep(1); os.remove(\"{}\"); os.remove(\"tmp.py\"); os.rename(\"tmp.exe\", \"{}\")".format(
            path.replace("\\", "\\\\"),
            path.replace("\\", "\\\\"))
            )

    Popen(["python", "tmp.py"])


class CodeCaveMemory:
    # Manage data storage in the binary itself.
    # Data access: CodeCaveMemory().data
    # Write data: CodeCaveMemory().write_data(data)

    def __init__(self, min_cave=128):
        self.min_cave = min_cave

        self.exe_path = self.get_exe_path()
        self.exe_data, self.exe_data_string = self.read_exe(self.exe_path)
        self.pe = pefile.PE(self.exe_path)

        self.init_memory()
    
    def init_memory(self):
        # Init memory information
        self.offsets_in_memory = False

        self.offset_ranges = self.find_code_caves()
        self.cave_sizes = list(map(lambda x: x[1] - x[0], self.offset_ranges))
        self.data, self.data_len = self.read_data()
        self.available_memory = sum(list(map(lambda x: x[1] - x[0], self.offset_ranges))) - self.data_len

        if self.available_memory < 0:
            raise Exception("MemoryError: CodeCaveMemory ran out of memory. Available memory: {}".format(
                self.available_memory))

        if not self.offsets_in_memory:
            self.save_offsets()
            self.init_memory()

    def get_exe_path(self):
        # Find out path to the binary itself
        path = os.path.realpath(__file__)
        exe_path = ".".join(path.split(".")[:-1]) + ".exe"
        return exe_path

    def read_exe(self, path):
        # Read the binary itself
        with open(path, "rb") as f:
            data = f.read()

        return (list(data), str(data, "latin-1"))

    def find_code_caves(self):
        # Check if code cave (offset addresses) information is already saved in the binary
        if "OSstart" in self.exe_data_string and "OSend" in self.exe_data_string:
            offset_ranges = pickle.loads(bytes(self.exe_data_string.split("OSstart")[-1].split("OSend")[0], "latin-1"))
            self.offsets_in_memory = True
        # If it is first run, find available code caves
        else:
            offset_ranges = []
            fd = open(self.exe_path, "rb")

            for section in self.pe.sections:
                if section.SizeOfRawData == 0:
                    continue

                pos = 0
                count = 0
                fd.seek(section.PointerToRawData, 0)
                data = fd.read(section.SizeOfRawData)

                for byte in data:
                    pos += 1
                    if byte == 0x00:
                        count += 1
                    else:
                        if count > self.min_cave:
                            raw_addr = section.PointerToRawData + pos - count - 1
                            offset_ranges.append([raw_addr, raw_addr + count - 1])
                        count = 0

        return offset_ranges

    def write_at_offsets(self, offsets, data):
        # Write data at offset range.
        # Make sure there is enough room for data.
        data_byte = 0
        for offset in range(offsets[0], offsets[1]+1):
            if data_byte == len(data):
                break
            self.exe_data[offset] = data[data_byte]
            data_byte += 1

        self.exe_data_string = str(bytes(self.exe_data), "latin-1")

    def save_offsets(self):
        # Save offset addresses information to most suitable offset address
        offsets_data = b"OSstart" + pickle.dumps(self.offset_ranges) + b"OSend"
        offset_save_cave = min(list(filter(lambda x: x > len(offsets_data), self.cave_sizes)))
        cave_offset_idx = self.cave_sizes.index(offset_save_cave)
        cave_offset = self.offset_ranges[cave_offset_idx]

        # Remove code cave that is used to store all other code cave information
        self.offset_ranges.pop(cave_offset_idx)

        offsets_data = b"OSstart" + pickle.dumps(self.offset_ranges) + b"OSend"
        self.write_at_offsets(cave_offset, offsets_data)

    def read_data(self):
        # Read data from the available offset addresses
        data = []
        for offset_range in self.offset_ranges:
            for offset in range(offset_range[0], offset_range[1]+1):
                data.append(self.exe_data[offset])

            data.pop(-1) # For some reason last byte in code cave is always 0x00

        data = str(bytes(data), "latin-1")
        # Exclude offset information from the data
        data_section1 = data.split("OSstart")[0]
        data_section2 = data.split("OSend")[-1]
        data = data_section1 + data_section2

        if len(list(set(data))) == 1:
            return (None, 0)

        data = bytes(data.split("Dstart")[-1].split("Dend")[0], "latin-1")
        data_len = len(data.strip(b"\x00")) + 10 # len(Dstart + Dend)
        return (pickle.loads(data), data_len)

    def write_data(self, data):
        # Write data to available offset addresses
        # data : Python object
        storage_data = b"Dstart" + pickle.dumps(data) + b"Dend"
        data_start = 0
        for offset_range in self.offset_ranges:
            size = offset_range[1] - offset_range[0]
            self.write_at_offsets(offset_range, storage_data[data_start:data_start+size])
            data_start += size

        self.init_memory()


if __name__ == "__main__":
    # Example of saving data acquired in the runtime to the program binary.
    CCM = CodeCaveMemory()

    print("{} bytes available in the CodeCaveMemory!".format(CCM.available_memory))
    print("Data saved in the binary:\n{}".format(json.dumps(CCM.data, indent=2)))

    user_message = input("Enter message: ")
    if len(user_message) != 0:
        if CCM.data:
            CCM.data["messages"].append(user_message)
            CCM.write_data(CCM.data)
        else:
            CCM.write_data({"messages": [user_message]})

    # Always save current binary at the end
    save_exe_data(CCM.exe_path, CCM.exe_data)
