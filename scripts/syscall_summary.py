import sys

def read_syscalls(file_path):
    syscalls = set()
    with open(file_path, 'r') as f:
        for line in f:
            clean = line.strip().strip('"').strip("'")
            if clean:
                syscalls.add(clean)
    return syscalls

def write_output(filename, data):
    with open(filename, 'w') as f:
        for syscall in sorted(data):
            f.write(syscall + '\n')

def write_summary(file1, file2, set1, set2, common, unique1, unique2):
    with open("summary.txt", "w") as f:
        f.write(
            f"File 1: {file1} — {len(set1)} syscalls\n"
            f"File 2: {file2} — {len(set2)} syscalls\n"
            f"Common syscalls: {len(common)}\n"
            f"Unique in {file1}: {len(unique1)}\n"
            f"Unique in {file2}: {len(unique2)}\n"
        )

def main():
    if len(sys.argv) != 3:
        print("Usage: python compare_syscalls.py <file1> <file2>")
        return

    file1, file2 = sys.argv[1], sys.argv[2]
    set1 = read_syscalls(file1)
    set2 = read_syscalls(file2)

    common  = set1 & set2
    unique1 = set1 - set2
    unique2 = set2 - set1

    write_output("common_syscalls.txt", common)
    write_output("unique_in_file1.txt", unique1)
    write_output("unique_in_file2.txt", unique2)
    write_summary(file1, file2, set1, set2, common, unique1, unique2)

    # Print counts
    print(f"File 1 ({file1}): {len(set1)} syscalls")
    print(f"File 2 ({file2}): {len(set2)} syscalls")
    print(f"Common: {len(common)} -> common_syscalls.txt")
    print(f"Unique in {file1}: {len(unique1)} -> unique_in_file1.txt")
    print(f"Unique in {file2}: {len(unique2)} -> unique_in_file2.txt")
    print("Summary written to summary.txt")

if __name__ == "__main__":
    main()

