# Network Protocol Mapping

**Network_Protocol_Mapping** is a robust tool designed for the effective mapping and management of network protocol assignments. This project focuses on parsing and analyzing log files associated with specific network protocols, providing insights and support for network management tasks.

## Table of Contents

- [Overview](#overview)
- [Assumptions](#assumptions)
- [Installation](#installation)
- [Usage](#usage)
- [Testing](#testing)
- [Thought Process](#thought-process)
- [Future Improvements](#future-improvements)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Overview

The tool is built to cater to standard log processing requirements, specifically tailored for two protocols: TCP and UDP. This focused approach allows for streamlined processing and analysis, making it suitable for use in environments where these protocols are prevalent.

## Assumptions

1. **Log Format**: The program exclusively supports the default log format, which must adhere to the specifications outlined in the documentation. Custom log formats are not accommodated in the current version.
   
2. **Version Support**: The implementation is designed to support only version 2 of the log files. Users should ensure that the input log files conform to this version for accurate processing.

3. **Protocol Scope**: The analysis is limited to two protocols, TCP and UDP. Future iterations of the program may consider the integration of additional protocols based on user feedback and requirements.

## VPC Flow Log Format

The VPC flow logs follow a specific format that captures various attributes of network traffic. Each log entry is typically structured as follows:

### Field Descriptions:

- **version**: The version of the log format (should be 2 for this implementation).
- **account-id**: The AWS account ID of the owner of the VPC.
- **interface-id**: The ID of the network interface.
- **srcaddr**: The source IP address of the traffic.
- **dstaddr**: The destination IP address of the traffic.
- **srcport**: The source port number.
- **dstport**: The destination port number.
- **protocol**: The protocol used (e.g., TCP, UDP).
- **packets**: The number of packets transferred.
- **bytes**: The number of bytes transferred.
- **start**: The start time of the flow log entry (in epoch time).
- **end**: The end time of the flow log entry (in epoch time).
- **action**: The action taken (e.g., ACCEPT or REJECT).
- **log-status**: The status of the log entry (e.g., OK).

This structured format allows the tool to efficiently parse and analyze log entries for the specified protocols, providing insights into network behavior.


## Installation

To set up the project, follow these steps:

**Clone the Repository**:
   ```bash
   git clone https://github.com/ShristiSuman/Network_Protocol_Mapping.git
   cd Network_Protocol_Mapping
   ```

## Usage

The program can be executed directly from the command line. Use the following command structure to run the program:

```bash
python3 Flow_Log_Parser.py Flow_Logs.txt Lookup_File.txt Output_Results.txt
```

This command processes the specified log file and outputs the results based on the mapped protocols.

## Testing

The project includes a comprehensive test suite to validate functionality. Tests are located in the `test` directory. To run the tests, execute:

```bash
python3 -m unittest discover -s test -p "test_*.py"
```

### Test Coverage
- **Unit Tests** validate individual functions for correctness.

## Thought Process

The development of **Network_Protocol_Mapping** was driven by the need for a specialized tool to handle specific network protocols. The following key considerations influenced the design:

- **Simplicity and Efficiency**: By focusing on two primary protocols (TCP and UDP), the tool minimizes complexity and maximizes performance in environments where these protocols are common.
  
- **User-Centric Design**: The tool is designed with user experience in mind, providing straightforward command-line usage and clear output to facilitate rapid analysis.
  
- **Modular Structure**: The codebase is organized into distinct modules, allowing for easy maintenance and potential future enhancements without significant refactoring.

## Future Improvements

Future iterations of this project could include:

- **Support for Additional Protocols**: Expanding the tool to handle more protocols based on user needs.
- **Custom Log Format Handling**: Implementing features that allow users to define their log formats.
- **Enhanced Reporting Features**: Developing advanced reporting options to provide deeper insights into network protocol usage and trends.