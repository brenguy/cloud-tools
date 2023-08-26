import boto3
import threading
import csv
import datetime
import re
import os
import fcntl
# Function to check if ACL allows public read or write
def is_public_acl(acl):
    for grant in acl['Grants']:
        grantee = grant['Grantee']
        if 'URI' in grantee and (grantee['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers' or
                                grantee['URI'] == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'):
            return True
    return False
# Worker function
def worker(bucket_name, csv_buffer):
    try:
        # Create a new S3 client for this thread
        s3 = boto3.client('s3')
        # Check if "Block All Public Access" is enabled for the bucket
        block_public_access = s3.get_public_access_block(Bucket=bucket_name)
        if block_public_access['PublicAccessBlockConfiguration']['BlockPublicAcls'] or \
           block_public_access['PublicAccessBlockConfiguration']['IgnorePublicAcls'] or \
           block_public_access['PublicAccessBlockConfiguration']['BlockPublicPolicy']:
            print(f"Skipping bucket {bucket_name} due to 'Block All Public Access' policy.")
            return
        paginator = s3.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(Bucket=bucket_name)
        rows = []
        for page in page_iterator:
            if 'Contents' in page:
                for obj in page['Contents']:
                    object_name = obj['Key']
                    object_acl = s3.get_object_acl(Bucket=bucket_name, Key=object_name)
                    if is_public_acl(object_acl):
                        rows.append({'objectName': object_name, 'ACL': 'Public'})
                    # Write to the CSV buffer when it fills up 1000 items
                    if len(rows) >= 1000:
                        write_csv_buffer(bucket_name, rows, csv_buffer)
                        rows.clear()
        # Write any remaining rows to the CSV buffer
        if len(rows) > 0:
            write_csv_buffer(bucket_name, rows, csv_buffer)
    except Exception as e:
        print(f"Error processing bucket {bucket_name}: {str(e)}")
# Function to write rows to the CSV buffer
def write_csv_buffer(bucket_name, rows, csv_buffer):
    csv_filename = f'{bucket_name}.csv'
    with csv_buffer[csv_filename]['lock']:
        with open(csv_filename, 'a', newline='') as csvfile:
            fieldnames = ['objectName', 'ACL']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerows(rows)
# Function to count objects in a bucket and update performance.csv
def count_objects(bucket_name, object_count_buffer):
    try:
        # Create a new S3 client for this thread
        s3 = boto3.client('s3')
        response = s3.list_objects_v2(Bucket=bucket_name)
        object_count = len(response.get('Contents', []))
        object_count_buffer[bucket_name] = object_count
    except Exception as e:
        print(f"Error counting objects in bucket {bucket_name}: {str(e)}")
# Main function
def main():
    start_time = datetime.datetime.now()
    # Initialize Boto3
    s3 = boto3.client('s3')
    # Define a regex pattern to match bucket names you want to skip
    skip_bucket_pattern = re.compile(r'^your-regex-pattern-here$')
    buckets = s3.list_buckets()['Buckets']
    # Count objects in each bucket and store in a dictionary
    object_count_buffer = {}
    for bucket in buckets:
        bucket_name = bucket['Name']
        # Skip buckets that match the regex pattern
        if skip_bucket_pattern.match(bucket_name):
            print(f"Skipping bucket {bucket_name} due to regex pattern.")
            continue
        count_objects(bucket_name, object_count_buffer)
    # Sort buckets by object count (highest to least)
    sorted_buckets = sorted(buckets, key=lambda bucket: object_count_buffer.get(bucket['Name'], 0), reverse=True)
    threads = []
    num_threads = min(len(sorted_buckets), 60)
    # Create a CSV buffer dictionary with locks for each CSV file
    csv_buffer = {}
    for bucket in sorted_buckets:
        bucket_name = bucket['Name']
        csv_filename = f'{bucket_name}.csv'
        csv_buffer[csv_filename] = {'lock': threading.Lock()}
        with open(csv_filename, 'w', newline='') as csvfile:
            fieldnames = ['objectName', 'ACL']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
    for i in range(num_threads):
        thread_buckets = sorted_buckets[i::num_threads]
        for bucket in thread_buckets:
            bucket_name = bucket['Name']
            # Skip buckets that match the regex pattern
            if skip_bucket_pattern.match(bucket_name):
                print(f"Skipping bucket {bucket_name} due to regex pattern.")
                continue
            thread = threading.Thread(target=worker, args=(bucket_name, csv_buffer))
            threads.append(thread)
            thread.start()
    for thread in threads:
        thread.join()
    # Count objects in each bucket
    for bucket in sorted_buckets:
        bucket_name = bucket['Name']
        count_objects(bucket_name, object_count_buffer)
    end_time = datetime.datetime.now()
    elapsed_time = end_time - start_time
    with open('performance.csv', 'a', newline='') as csvfile:
        fieldnames = ['Timestamp', 'Event']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writerow({'Timestamp': start_time, 'Event': 'Script Start'})
        writer.writerow({'Timestamp': end_time, 'Event': 'Script End'})
        writer.writerow({'Timestamp': elapsed_time, 'Event': 'Elapsed Time'})
if __name__ == '__main__':
    main()