# Steps to accomplish this:
# 1) Read and parse the VPC flow log entries.
# 2) For each log entry, extract relevant columns (destination port and protocol).
# 3) Use the lookup table to determine if there is a corresponding tag for each entry.
# 4) Update counts for both tags and port/protocol combinations based on matches.
    

import sys, os
from collections import defaultdict

EXPECTED_FIELDS = 14
VERSION = "2"

def load_lookup_file(file_path):
    # Dictionary to store the mapping of port and protocol combination to tag.
    lookup_table = {}

    # Open the lookup file
    with open(file_path, 'r') as file:
        try:
            # Skip the header line
            next(file)  
        except StopIteration:
            # Handle empty files gracefully
            return lookup_table

        # Read each line in the file
        for line in file:
            # Strip whitespaces and skip empty lines
            line = line.strip()
            if not line:
                continue
            
            # Split the line by commas
            dstport, protocol, tag = line.split(',')
            # Store the mapping in the lookup table
            lookup_table[(int(dstport), protocol.strip().lower())] = tag.strip()

    return lookup_table


def process_flow_logs(flow_log_file, lookup_table):
    processed_logs = []
    tag_counts = defaultdict(int)
    port_protocol_counts = defaultdict(int)
    untagged_count = 0

    # Open the flow log file
    with open(flow_log_file, 'r') as file:

        # Read each line in the flow log file
        for line in file:
            # Strip whitespaces and skip empty lines
            line = line.strip()
            # Skip comments or empty lines
            if not line or line.startswith("#"):
                continue  

            # Split the line into fields
            fields = line.split()

            # Ensure enough fields exist in the log
            if len(fields) < EXPECTED_FIELDS: 
                raise ValueError(f"Malformed flow log entry: {line}")
            
            try:
                # Extract Version
                version = fields[0]
                # Skip logs not in version 2 format
                if version != VERSION:
                    continue  

                # Extract Destination port
                dstport = int(fields[6])  

                # Extract protocol (6 for TCP, 17 for UDP, etc)
                protocol = fields[7] 
                
                # Protocol mapping 
                protocol_map = {
                    '6': 'tcp',
                    '17': 'udp'
                }

                # Map protocol number to string
                if protocol in protocol_map:
                    protocol_str = protocol_map[protocol]
                elif protocol.isdigit():
                    protocol_str = 'icmp'  # Defaulting to ICMP for other cases
                    print(f"Unknown protocol number found: {protocol}")
                else:
                    raise ValueError(f"Non-numeric protocol found: {protocol}")

                # Lookup the tag based on the (dstport, protocol) combination
                tag = lookup_table.get((dstport, protocol_str), 'Untagged')

                # Append the processed log entry with the tag
                processed_logs.append({
                    'dstport': dstport,
                    'protocol': protocol_str,
                    'tag': tag
                })

                if tag == 'Untagged':
                    untagged_count += 1
                else:
                    tag_counts[tag] += 1
                
                # Track port/protocol combination
                port_protocol_counts[(dstport, protocol_str)] += 1

            except IndexError:
                 # Skip lines that do not have enough fields
                print(f"Error processing line: {line}")
                continue 

    return tag_counts, port_protocol_counts, untagged_count



# Function to write results to an output file
def write_output(output_file, tag_counts, port_protocol_counts, untagged_count):

    with open(output_file, mode='w') as file:
        # Write tag counts
        file.write("Tag Counts:\n")
        file.write("Tag,Count\n")
        for tag, count in tag_counts.items():
            file.write(f"{tag},{count}\n")
        file.write(f"Untagged,{untagged_count}\n\n")
        
        # Write port/protocol combination counts
        file.write("Port/Protocol Combination Counts:\n")
        file.write("Port,Protocol,Count\n")
        for (port, protocol), count in port_protocol_counts.items():
            file.write(f"{port},{protocol},{count}\n")



# Main driver function to run the program
def main(flow_log_file, lookup_file, output_file):

    # Validate file paths
    for file_path in [flow_log_file, lookup_file]:
        if not os.path.isfile(file_path):
            print(f"Error: The file '{file_path}' does not exist.")
            sys.exit(1)

    # Load the lookup table and process the flow logs
    lookup_table = load_lookup_file(lookup_file)
    tag_counts, port_protocol_counts, untagged_count = process_flow_logs(flow_log_file, lookup_table)
    
    # Output the results to the specified file
    write_output(output_file, tag_counts, port_protocol_counts, untagged_count)

    print(f"Processing completed. Results written to {output_file}")

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python flow_log_parser.py <flow_log_file> <lookup_table_file> <output_file>")
        sys.exit(1)
    
    flow_file = sys.argv[1]
    lookup_file = sys.argv[2]
    output_file = sys.argv[3]

    main(flow_file, lookup_file, output_file)