import re
import os
import sys

# Define the input and output file names
input_files = [
    #"unique_native_methods.txt"
     "jre_used_natives.txt", 
     "all_target_dep_natives.txt"
    # Add other input file names here as needed
]
output_file = "formatted_methods.txt"

# Check if all input files exist before proceeding
print("Checking for required input files...")
for file in input_files:
    if not os.path.isfile(file):
        print(f"ERROR: Input file not found: {file}")
        print(f"Please create '{file}' and add the native methods to it.")
        sys.exit(1)

# Open the output file for writing, which will overwrite previous content
with open(output_file, "w") as out:
    print("Reading and formatting methods from input files...")
    # Process each input file
    for file in input_files:
        print(f"Processing '{file}'...")
        try:
            with open(file, "r") as f:
                input_methods_content = f.read()
        except IOError as e:
            print(f"ERROR: Could not read file {file}. Reason: {e}")
            continue  # Skip to the next file if an error occurs

        # Iterate through each line of the input file's content
        for line in input_methods_content.strip().split('\n'):
            # Remove the leading number and any whitespace
            stripped_line = re.sub(r'^\d+\.\s*', '', line).strip()
            
            # First, check if the line is in the expected `<class: method(...)>` format
            match = re.search(r'^<([^:]+):.*?\s+(\w+)\s*\(', stripped_line)
            
            if match:
                class_name = match.group(1)
                method_name = match.group(2)
                
                # Combine the class and method name with a period
                formatted_method = f"{class_name}.{method_name}"
                out.write(formatted_method + "\n")
                # print(formatted_method) # Uncomment for verbose output
            elif '.' in stripped_line:
                # If it doesn't match, check if it looks like a pre-formatted method
                # This handles cases where the input is already in the final format
                out.write(stripped_line + "\n")
            else:
                # If a line doesn't match any expected format, print a warning
                print(f"Warning: Could not parse line: {line}")

print(f"\nDone! Formatted methods from all files have been saved to {output_file}.")
