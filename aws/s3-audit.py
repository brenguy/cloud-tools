import boto3
import threading
import csv
import datetime
import re
import os
import pandas as pd
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
def worker(bucket_name, csv_buffer, object_key_buffer):
    try:
        print(f"Starting to audit bucket: {bucket_name} with len(object_key_buffer[bucket_name]) objects")
        object_threads = []
        if len(object_key_buffer[bucket_name]) > 400000:
            inner_num_threads=64
        elif len(object_key_buffer[bucket_name]) > 300000:
            inner_num_threads=32
        elif len(object_key_buffer[bucket_name]) > 200000:
            inner_num_threads=16
        elif len(object_key_buffer[bucket_name]) > 100000:
            inner_num_threads=8
        elif len(object_key_buffer[bucket_name]) > 10000:
            inner_num_threads=4
        else:
            inner_num_threads=0
        if inner_num_threads > 0 :
            for i in range(inner_num_threads):
                print(f"Starting the multithreaded audit for {bucket_name}")
                objects_to_audit = object_key_buffer[bucket_name][i::inner_num_threads]
                object_thread = threading.Thread(target=scaled_audit_objects, args=(bucket_name, csv_buffer, objects_to_audit))
                object_threads.append(object_thread)
                object_thread.start()
        else:
            s3 = boto3.client('s3')
            rows = []
            for object_name in object_key_buffer[bucket_name]:
                print(f"Auditing with single thread: {object_name}.")
                object_acl = s3.get_object_acl(Bucket=bucket_name, Key=object_name)
                if is_public_acl(object_acl):
                    rows.append({'objectName': object_name, 'ACL': 'Public'})
                    # Write to the CSV buffer when it fills up 1000 items
                    if len(rows) >= 1000:
                        write_csv_buffer(bucket_name, rows, csv_buffer)
                        rows.clear()
                    elif object_name == object_key_buffer[bucket_name][-1]:
                        write_csv_buffer(bucket_name, rows, csv_buffer)
                        rows.clear()
        if inner_num_threads > 0 :
            for object_thread in object_threads:
                object_thread.join()
        else:
            del(object_key_buffer[bucket_name])
    except Exception as e:
        print(f"Error processing bucket {bucket_name}: {str(e)}")

def scaled_audit_objects(bucket_name, csv_buffer, objects_to_audit):
    try:
        s3 = boto3.client('s3')
        rows = []
        for object_name in objects_to_audit:
            print(f"Auditing with multithreads: {object_name}.")
            object_acl = s3.get_object_acl(Bucket=bucket_name, Key=object_name)
            if is_public_acl(object_acl):
                rows.append({'objectName': object_name, 'ACL': 'Public'})
                if len(rows) >= 1000:
                    write_csv_buffer(bucket_name, rows, csv_buffer)
                    rows.clear()
                elif object_name == objects_to_audit[-1]:
                    write_csv_buffer(bucket_name, rows, csv_buffer)
                    rows.clear()
    except Exception as e:
        print(f"Error processing bucket with multithreads for {bucket_name}: {str(e)}")

# Function to write rows to the CSV buffer
def write_csv_buffer(bucket_name, rows, csv_buffer):
    try:
        csv_filename = f'{bucket_name}.csv'
        with csv_buffer[csv_filename]['lock']:
            with open(csv_filename, 'a', newline='') as csvfile:
                fieldnames = ['objectName', 'ACL']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writerows(rows)
    except Exception as e:
        print(f"Error writing rows of found public items to bucket for {bucket_name}: {str(e)}")
# Function to count objects in a bucket and update performance.csv
def count_objects(bucket_name, object_count_buffer, object_key_buffer):
    print(f"Started to count them objects")
    object_key_buffer[bucket_name] = []
    try:
        s3 = boto3.client('s3')
        paginator = s3.get_paginator('list_objects_v2')
        object_count = 0 
        for page in paginator.paginate(Bucket=bucket_name):
            print(f"Inside a paginator to count them objects")
            if 'Contents' in page:
                object_count += len(page['Contents'])
                for obj in page['Contents']:
                    object_key_buffer[bucket_name].append(obj['Key'])
        object_count_buffer[bucket_name] = object_count
    except Exception as e:
        print(f"Error counting objects in bucket {bucket_name}: {str(e)}")

# Filter down buckets for the audit
def filter_buckets(buckets, filtered_buckets_list,bucket_master_report):
    s3Client = boto3.client('s3')
    skip_bucket_pattern = re.compile(r'regex')
    for bucket in buckets:
        if skip_bucket_pattern.match(bucket):
            bucket_master_report[bucket]="Ignored by Regex"
            print(f"Skipping bucket {bucket} due to regex pattern.")
        else:
            try:
                print(f"Checking if public access is blocked explicitly on bucket: {bucket}")
                block_public_access = s3Client.get_public_access_block(Bucket=bucket)
                if block_public_access['PublicAccessBlockConfiguration']['BlockPublicAcls'] and block_public_access['PublicAccessBlockConfiguration']['IgnorePublicAcls'] and block_public_access['PublicAccessBlockConfiguration']['BlockPublicPolicy']:
                        print(f"Skipping bucket {bucket} due to 'Block All Public Access' policy.")
                        bucket_master_report[bucket]="Explicit public access block"
                else:
                    filtered_buckets_list.append(bucket)
            except Exception as e:
                print(f"Bucket: {bucket} does not block public access explicitly")
                filtered_buckets_list.append(bucket)

def main():
    start_time = datetime.datetime.now()
    buckets = []
    s3 = boto3.resource('s3')
    for bucket in s3.buckets.all():
        buckets.append(bucket.__getattribute__('name'))
    # Filter down the list
    filtered_buckets_list = []
    bucket_master_report = {}
    filter_buckets(buckets, filtered_buckets_list, bucket_master_report)
    # Setup threads 
    threads = []
    num_threads = min(len(filtered_buckets_list), 60)
    # Count objects in each bucket and store in a dictionary for later use in sorting and determining num of threads.
    object_count_buffer = {}
    object_key_buffer = {}
    print(f"About to count them objects yo")
    for i in range(num_threads):
        thread_buckets = filtered_buckets_list[i::num_threads]
        for bucket in thread_buckets:
            thread = threading.Thread(target=count_objects, args=(bucket, object_count_buffer,object_key_buffer))
            threads.append(thread)
            thread.start()
    for thread in threads:
        thread.join()
    # Sort buckets by object count (highest to least)
    sorted_buckets = sorted(filtered_buckets_list, key=lambda bucket: object_count_buffer.get(bucket, 0), reverse=True)
    # Create a CSV buffer dictionary with locks for each CSV file
    csv_buffer = {}
    # Reset threads 
    threads = []
    for bucket in sorted_buckets:
        csv_filename = f'{bucket}.csv'
        csv_buffer[csv_filename] = {'lock': threading.Lock()}
        with open(csv_filename, 'w', newline='') as csvfile:
            fieldnames = ['objectName', 'ACL']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
    for i in range(num_threads):
        thread_buckets = sorted_buckets[i::num_threads]
        for bucket in thread_buckets:
            thread = threading.Thread(target=worker, args=(bucket, csv_buffer, object_key_buffer))
            threads.append(thread)
            thread.start()
    for thread in threads:
        thread.join()
    end_time = datetime.datetime.now()
    elapsed_time = end_time - start_time
    for bucketfile in buckets:
        csv_file_name = f'{bucketfile}.csv'
        if os.path.exists(csv_file_name):
            try:
                # Load the CSV file into a DataFrame using pandas
                df = pd.read_csv(csv_file_name)
                # Determine the number of rows (excluding the header)
                row_count = len(df)
                bucket_master_report[bucketfile] = row_count
                print(f'File {csv_file_name} loaded. Rows (excluding header): {row_count}')
            except Exception as e:
                print(f'Error loading file {csv_file_name}: {str(e)}')
        else:
            print(f'File {csv_file_name} not found.')
    with open('master-report.csv', 'a', newline='') as csvfile:
        fieldnames = ['BucketName','PublicStatus']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        for key, value in bucket_master_report.items():
            writer.writerow({'BucketName': str(key),'PublicStatus': str(value) })
    with open('performance.csv', 'a', newline='') as csvfile:
        fieldnames = ['TotalObjects','Timestamp', 'Event']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writerow({'TotalObjects': str(object_count_buffer),'Timestamp': start_time, 'Event': 'Script Start'})
        writer.writerow({'TotalObjects': str(object_count_buffer),'Timestamp': end_time, 'Event': 'Script End'})
        writer.writerow({'TotalObjects': str(object_count_buffer),'Timestamp': elapsed_time, 'Event': 'Elapsed Time'})
if __name__ == '__main__':
    main()