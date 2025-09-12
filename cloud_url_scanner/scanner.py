import argparse
from utils import check_url_access, check_indexed_content, simulate_write_access
from aws_checker import check_s3_permissions  # optional

def main():
    parser = argparse.ArgumentParser(description="Cloud URL Misconfiguration Scanner")
    parser.add_argument("-i", "--input", required=True, help="Path to input file with URLs")
    parser.add_argument("--aws", action="store_true", help="Enable AWS S3 checks (requires boto3)")
    args = parser.parse_args()

    with open(args.input, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    for url in urls:
        print(f"\n🔍 Scanning: {url}")
        access = check_url_access(url)
        indexed = check_indexed_content(url)
        writable = simulate_write_access(url)

        print(f"  ✅ Public Access: {'Yes' if access else 'No'}")
        print(f"  📂 Indexed Content: {'Yes' if indexed else 'No'}")
        print(f"  ✍️ Write Access (simulated): {'Possible' if writable else 'Restricted'}")

        if args.aws and "s3.amazonaws.com" in url:
            perms = check_s3_permissions(url)
            print(f"  🔐 S3 Permissions: {perms}")

if __name__ == "__main__":
    main()