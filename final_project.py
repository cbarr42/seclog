from datetime import datetime, timedelta

# identify how many days to look back in the log files
cutoffauth = datetime.now() - timedelta(days=5)
cutoffufw = datetime.now() - timedelta(days=2)

# log file paths in Ubuntu
authlog = '/var/log/auth.log'
ufwlog = '/var/log/ufw.log'

number = 0
# check auth.log for failed logons
with open("logoutput.txt", "w") as f:
    print('Failed Logons', file=f)
    print('/var/log/auth.log', file=f)
    with open(authlog, 'r') as file:
        for line in file:
            # search for "authentication fail" in each line of the log file
            if 'authentication fail' in line:
                # identify timestamp at beginning of log
                timestamp_str = line.split()[0]
                time = timestamp_str.split('.')[0]
                user = line.split()[-1]
                number = number + 1
                try:
                    log_timestamp = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f%z')
                    # convert log_timestamp to offset-naive (UTC) for comparison
                    log_timestamp_naive = log_timestamp.replace(tzinfo=None)
                    if log_timestamp_naive >= cutoffauth:
                        print(number, ') ', time, user, file=f)
                except ValueError:
                    # handle cases where the timestamp format doesn't match
                    pass

number = 0
with open("logoutput.txt", "a") as f:
    print(file=f)
    print('sudo Usage', file=f)
    print('/var/log/auth.log', file=f)
    with open(authlog, 'r') as file:
        for line in file:
            # search for "authentication fail" in each line of the log file
            if 'COMMAND' in line and 'sudo' in line:
                # identify timestamp at beginning of log
                timestamp_str = line.split()[0]
                time = timestamp_str.split('.')[0]
                user = line.split()[3]
                command = line.split()[11].split('/')[3]
                command2 = ' '.join(line.split()[12:])
                number = number + 1
                try:
                    log_timestamp = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f%z')
                    # convert log_timestamp to offset-naive (UTC) for comparison
                    log_timestamp_naive = log_timestamp.replace(tzinfo=None)
                    if log_timestamp_naive >= cutoffauth:
                        print(number, ') ', time, user, command, command2, file=f)
                except ValueError:
                    # handle cases where the timestamp format doesn't match
                    pass

number = 0
with open("logoutput.txt", "a") as f:
    print(file=f)
    print('Blocked Traffic', file=f)
    print('/var/log/ufw.log', file=f)
    with open(ufwlog, 'r') as file:
        for line in file:
            # search for "block" in each line of the log file
            if 'BLOCK' in line:
                # identify timestamp at beginning of log
                # format output to only include interface, source, and destination
                timestamp_str = line.split()[0]
                time = timestamp_str.split('.')[0]
                ufwint = line.split()[5]
                ufwsrc = line.split()[8]
                ufwdest = line.split()[9]

                try:
                    log_timestamp = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f%z')
                    # convert log_timestamp to offset-naive (UTC) for comparison
                    log_timestamp_naive = log_timestamp.replace(tzinfo=None)
                    if log_timestamp_naive >= cutoffufw and not ufwsrc.startswith('SRC=fe80'):
                        number = number + 1
                        print(number, ') ', time, ufwint, ufwsrc, ufwdest, file=f)
                except ValueError:
                    # handle cases where the timestamp format doesn't match
                    pass

print("Please review 'logoutput.txt' in current directory")