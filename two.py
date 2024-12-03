import re
import pandas as pd
from collections import Counter

# Accessing the log file
with open('one.txt', 'r') as file:
    log_data = file.read()

# regex pattern used to match and extract data from each line of a log file
log_pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<datetime>[^\]]+)\] "(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\d+)(?: "(?P<message>[^"]+)")?'
)

# Parsing the log data
parsed_logs = []
for line in log_data.strip().split("\n"):
    match = log_pattern.match(line)
    if match:
        parsed_logs.append(match.groupdict())

# Converting into data_frame
df = pd.DataFrame(parsed_logs)

# Task 1: IP Address and Request Count
task1 = Counter(df['ip'])
task1_sorted = sorted(task1.items(), key=lambda x: x[1], reverse=True)
task1 = sorted(task1.items(), key=lambda x: x[1], reverse=True)

# printing task1
header_ip = "IP Address"
header_count = "Request Count"
print(f"{header_ip:<20}{header_count:<15}")
for key, value in task1:
    print(f"{key:<20}{value:<15}")

# Create DataFrame for Task 1
task1_df = pd.DataFrame(task1_sorted, columns=['IP Address', 'Request Count'])

# Task 2: Most Frequently Accessed Endpoint
task2 = Counter(df['endpoint'])
mx = max(task2.values())
task2_result = [(key, mx) for key in task2 if task2[key] == mx]

#printing task2
print("Most Frequently Accessed Endpoint:")
mx=max(task2.values())
for key in task2:
    if task2[key]==mx:
        print("{}  (Accessed {} times)".format(key,mx))

# Create DataFrame for Task 2
task2_df = pd.DataFrame(task2_result, columns=['Endpoint', 'Access Count'])

# Task 3: Suspicious Activity Detected (Failed Login Attempts)
failed_logins = df[df['status'] == '401']
failed_login_count = failed_logins['ip'].value_counts()
 #printing task3
print("Suspecious activity detection")
print(f"{'IP Address':<20} {'Failed Login Attempts'}")
for ip, count in failed_login_count.items():
    print(f"{ip:<20} {count}")

# Create DataFrame for Task 3
task3_df = pd.DataFrame(failed_login_count).reset_index()
task3_df.columns = ['IP Address', 'Failed Login Attempts']
print()

# Saving all results to CSV files
task1_df.to_csv('task1_ip_request_count.csv', index=False)
task2_df.to_csv('task2_most_accessed_endpoint.csv', index=False)
task3_df.to_csv('task3_suspicious_activity.csv', index=False)

print("Results saved to CSV files:")
print("task1_ip_request_count.csv")
print("task2_most_accessed_endpoint.csv")
print("task3_suspicious_activity.csv")
