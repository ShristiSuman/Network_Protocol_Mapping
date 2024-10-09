import unittest
import os
from Flow_Log_Parser import load_lookup_file, process_flow_logs

class TestFlowLogParser(unittest.TestCase):

    def setUp(self):

        self.flow_logs_file_1 = 'test_flow_log_1.txt'
        self.lookup_file_1 = 'test_lookup_table_1.txt'

        self.flow_logs_file_2 = 'test_flow_log_2.txt'

        self.empty_flow_log_file = 'empty_flow_log.txt'
        self.empty_lookup_file = 'empty_lookup_table.txt'

        self.malformed_flow_log_file = 'malformed_flow_log.txt'

        self.flow_logs_content_1 = """
            2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 49153 443 6 25 20000 1620140761 1620140821 ACCEPT OK
            2 123456789012 eni-0a1b2c3d 10.0.1.202 198.51.100.3 49154 80 6 25 20000 1620140762 1620140822 ACCEPT OK
            2 123456789012 eni-0a1b2c3d 10.0.1.203 198.51.100.4 49155 53 17 25 20000 1620140763 1620140823 ACCEPT OK
        """

        self.lookup_table_content_1 = """# Port,Protocol,Tag
            443,tcp,HTTPS
            80,tcp,HTTP
            53,udp,DNS
            22,tcp,SSH
        """

        self.flow_log_content_2 = """2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 49153 999 6 25 20000 1620140761 1620140821 ACCEPT OK
            2 123456789012 eni-0a1b2c3d 10.0.1.202 198.51.100.3 49154 8080 17 25 20000 1620140762 1620140822 ACCEPT OK
        """

        self.empty_flow_log_content = ""
        self.empty_lookup_table_content = ""

        self.malformed_flow_log_content = """2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 49153 443 6 25 20000 1620140761 1620140821 ACCEPT OK
            2 123456789012 eni-0a1b2c3d 10.0.1.202 198.51.100.3 80
        """

        # Write the test files
        with open(self.flow_logs_file_1, 'w') as f:
            f.write(self.flow_logs_content_1)
        
        with open(self.lookup_file_1, 'w') as f:
            f.write(self.lookup_table_content_1)

        with open(self.flow_logs_file_2, 'w') as f:
            f.write(self.flow_log_content_2)
        
        with open(self.empty_flow_log_file, 'w') as f:
            f.write(self.empty_flow_log_content)

        with open(self.empty_lookup_file, 'w') as f:
            f.write(self.empty_lookup_table_content)

        with open(self.malformed_flow_log_file, 'w') as f:
            f.write(self.malformed_flow_log_content)


    def tearDown(self):
        # Remove test files after tests are complete
        os.remove(self.flow_logs_file_1)
        os.remove(self.lookup_file_1)
        os.remove(self.flow_logs_file_2)
        os.remove(self.empty_flow_log_file)
        os.remove(self.empty_lookup_file)
        os.remove(self.malformed_flow_log_file)

        # Remove the duplicate log file and the comment log file
        if os.path.exists('duplicate_flow_log.txt'):
            os.remove('duplicate_flow_log.txt')
        
        if os.path.exists('flow_log_with_comments.txt'):
            os.remove('flow_log_with_comments.txt')
        
        if os.path.exists('large_flow_log.txt'):
            os.remove('large_flow_log.txt')
        
        if os.path.exists('non_integer_flow_log.txt'):
            os.remove('non_integer_flow_log.txt')


    # Testing the lookup file
    def test_load_lookup_file(self):
        lookup_table = load_lookup_file(self.lookup_file_1)
        expected_output = {
            (443, 'tcp'): 'HTTPS',
            (80, 'tcp'): 'HTTP',
            (53, 'udp'): 'DNS',
            (22, 'tcp'): 'SSH',
        }
        self.assertEqual(lookup_table, expected_output)


    # Testing the main process flow logs file
    def test_process_flow_logs(self):
        lookup_table = load_lookup_file(self.lookup_file_1)
        tag_counts, port_protocol_counts, untagged_count = process_flow_logs(self.flow_logs_file_1, lookup_table)
        
        expected_tag_counts = {'HTTPS': 1, 'HTTP': 1, 'DNS': 1}
        expected_port_protocol_counts = {
            (443, 'tcp'): 1,
            (80, 'tcp'): 1,
            (53, 'udp'): 1,
        }
        self.assertEqual(tag_counts, expected_tag_counts)
        self.assertEqual(port_protocol_counts, expected_port_protocol_counts)
        self.assertEqual(untagged_count, 0)

    
    
    # Test how the parser handles flow logs with ports/protocols that do not exist in the lookup table
    def test_process_flow_logs_with_unknown(self):
        lookup_table = load_lookup_file(self.empty_lookup_file)
        tag_counts, port_protocol_counts, untagged_count = process_flow_logs(self.flow_logs_file_2, lookup_table)
        
        expected_tag_counts = {}
        expected_port_protocol_counts = {
            (999, 'tcp'): 1,
            (8080, 'udp'): 1,
        }
        self.assertEqual(tag_counts, expected_tag_counts)
        self.assertEqual(port_protocol_counts, expected_port_protocol_counts)
        self.assertEqual(untagged_count, 2)

    
    # Case where log file is empty
    def test_empty_flow_log(self):
        lookup_table = load_lookup_file(self.lookup_file_1)
        tag_counts, port_protocol_counts, untagged_count = process_flow_logs(self.empty_flow_log_file, lookup_table)

        self.assertEqual(tag_counts, {})
        self.assertEqual(port_protocol_counts, {})
        self.assertEqual(untagged_count, 0)

    
    # Case where lookup file is empty
    def test_empty_lookup_table(self):
        lookup_table = load_lookup_file(self.empty_lookup_file)
        tag_counts, port_protocol_counts, untagged_count = process_flow_logs(self.flow_logs_file_1, lookup_table)

        self.assertEqual(tag_counts, {})
        self.assertEqual(port_protocol_counts, {
            (443, 'tcp'): 1,
            (80, 'tcp'): 1,
            (53, 'udp'): 1,
        })
        self.assertEqual(untagged_count, 3) 

    
    # Case where log file contains comments
    def test_flow_log_with_comments(self):
        flow_log_with_comments = """# This is a comment
# Another comment
2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 49153 443 6 25 20000 1620140761 1620140821 ACCEPT OK
"""
        with open('flow_log_with_comments.txt', 'w') as f:
            f.write(flow_log_with_comments)

        lookup_table = load_lookup_file(self.lookup_file_1)
        tag_counts, port_protocol_counts, untagged_count = process_flow_logs('flow_log_with_comments.txt', lookup_table)

        expected_tag_counts = {'HTTPS': 1}
        expected_port_protocol_counts = {
            (443, 'tcp'): 1,
        }
        self.assertEqual(tag_counts, expected_tag_counts)
        self.assertEqual(port_protocol_counts, expected_port_protocol_counts)
        self.assertEqual(untagged_count, 0)

    
    # Case where duplicate values are present in log files
    def test_process_flow_logs_with_duplicates(self):
        duplicate_flow_log_content = """2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 49153 443 6 25 20000 1620140761 1620140821 ACCEPT OK
        2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 49153 443 6 25 20000 1620140761 1620140821 ACCEPT OK
        2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2  49154 80 6 25 20000 1620140761 1620140821 ACCEPT OK
        """
        with open('duplicate_flow_log.txt', 'w') as f:
            f.write(duplicate_flow_log_content)

        lookup_table = load_lookup_file(self.lookup_file_1)
        tag_counts, port_protocol_counts, untagged_count = process_flow_logs('duplicate_flow_log.txt', lookup_table)

        expected_tag_counts = {'HTTPS': 2, 'HTTP': 1}
        expected_port_protocol_counts = {
            (443, 'tcp'): 2,
            (80, 'tcp'): 1,
        }
        self.assertEqual(tag_counts, expected_tag_counts)
        self.assertEqual(port_protocol_counts, expected_port_protocol_counts)
        self.assertEqual(untagged_count, 0)

    
    # Case where the log file is malformed (Less than 14 fields)
    def test_malformed_flow_log(self):
        with open('malformed_flow_log.txt', 'w') as f:
            f.write(self.malformed_flow_log_content)

        lookup_table = load_lookup_file(self.lookup_file_1)
        with self.assertRaises(ValueError):
            process_flow_logs('malformed_flow_log.txt', lookup_table)
    

    # Test for large number of flow log entries
    def test_large_input_file(self):
    
        large_flow_log_content = "\n".join(
            f"2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.{i} 49153 443 6 25 20000 1620140761 1620140821 ACCEPT OK"
            for i in range(1, 10001)  # Create 10,000 entries
        )
        with open('large_flow_log.txt', 'w') as f:
            f.write(large_flow_log_content)

        lookup_table = load_lookup_file(self.lookup_file_1)
        tag_counts, port_protocol_counts, untagged_count = process_flow_logs('large_flow_log.txt', lookup_table)

        expected_tag_counts = {'HTTPS': 10000}
        expected_port_protocol_counts = {
            (443, 'tcp'): 10000,
        }
        self.assertEqual(tag_counts, expected_tag_counts)
        self.assertEqual(port_protocol_counts, expected_port_protocol_counts)
        self.assertEqual(untagged_count, 0)
    

    # Case where the log file contains non-integer values for ports
    def test_process_flow_logs_with_non_integer_ports(self):
        non_integer_flow_log_content = """2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 49153 non_integer_port 6 25 20000 1620140761 1620140821 ACCEPT OK
        2 123456789012 eni-0a1b2c3d 10.0.1.202 198.51.100.3 49154 another_non_integer 17 25 20000 1620140762 1620140822 ACCEPT OK
        """
        
        with open('non_integer_flow_log.txt', 'w') as f:
            f.write(non_integer_flow_log_content)

        lookup_table = load_lookup_file(self.lookup_file_1)
        with self.assertRaises(ValueError):
            process_flow_logs('non_integer_flow_log.txt', lookup_table)


if __name__ == '__main__':
    unittest.main()