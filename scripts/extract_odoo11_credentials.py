#!/usr/bin/env python3
"""
Extract Certificate and CAF from Odoo 11 Database
Fast-Track Migration Script

Usage:
    python extract_odoo11_credentials.py --db odoo11_eergygroup --user odoo --output /tmp/export_odoo11

Requirements:
    pip install psycopg2-binary
"""

import argparse
import base64
import os
import sys
from pathlib import Path
from datetime import datetime

try:
    import psycopg2
except ImportError:
    print("❌ Error: psycopg2 not installed")
    print("Install with: pip install psycopg2-binary")
    sys.exit(1)


class Odoo11Extractor:
    """Extract critical DTE data from Odoo 11 database"""

    def __init__(self, db_name, db_user, db_host='localhost', db_port=5432, db_password=None):
        self.db_name = db_name
        self.db_user = db_user
        self.db_host = db_host
        self.db_port = db_port
        self.db_password = db_password
        self.conn = None

    def connect(self):
        """Connect to Odoo 11 database"""
        try:
            print(f"🔌 Connecting to database: {self.db_name}")
            self.conn = psycopg2.connect(
                dbname=self.db_name,
                user=self.db_user,
                host=self.db_host,
                port=self.db_port,
                password=self.db_password
            )
            print("✅ Connected successfully")
            return True
        except psycopg2.Error as e:
            print(f"❌ Database connection failed: {e}")
            return False

    def extract_certificate(self, output_dir):
        """Extract digital certificate from sii.firma model"""
        print("\n📜 Extracting Digital Certificate...")

        cursor = self.conn.cursor()

        # Check if sii.firma table exists
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'sii_firma'
            )
        """)
        if not cursor.fetchone()[0]:
            print("⚠️  Table 'sii_firma' not found - trying alternative names...")
            cursor.execute("""
                SELECT table_name FROM information_schema.tables
                WHERE table_name LIKE '%firma%' OR table_name LIKE '%cert%'
            """)
            tables = cursor.fetchall()
            print(f"Found tables: {tables}")
            return False

        # Extract active certificate
        cursor.execute("""
            SELECT
                id,
                name,
                file_content,
                password,
                subject_serial_number,
                expire_date,
                state
            FROM sii_firma
            WHERE state IN ('valid', 'incomplete')
              AND (expire_date IS NULL OR expire_date > CURRENT_DATE)
            ORDER BY expire_date DESC NULLS LAST
            LIMIT 1
        """)

        row = cursor.fetchone()
        if not row:
            print("❌ No valid certificate found in database")
            return False

        cert_id, name, file_content, password, rut, expire_date, state = row

        print(f"✅ Certificate found:")
        print(f"   ID: {cert_id}")
        print(f"   Name: {name}")
        print(f"   RUT: {rut}")
        print(f"   Expires: {expire_date}")
        print(f"   State: {state}")

        # Save .p12 file
        cert_path = os.path.join(output_dir, 'certificado_produccion.p12')
        with open(cert_path, 'wb') as f:
            f.write(file_content)
        print(f"✅ Certificate saved: {cert_path}")

        # Save password and metadata
        info_path = os.path.join(output_dir, 'certificado_info.txt')
        with open(info_path, 'w') as f:
            f.write(f"Certificate Information\n")
            f.write(f"{'=' * 50}\n")
            f.write(f"Extracted: {datetime.now().isoformat()}\n")
            f.write(f"Source DB: {self.db_name}\n")
            f.write(f"ID: {cert_id}\n")
            f.write(f"Name: {name}\n")
            f.write(f"RUT: {rut}\n")
            f.write(f"Expires: {expire_date}\n")
            f.write(f"State: {state}\n")
            f.write(f"\n")
            f.write(f"Password: {password}\n")
        print(f"✅ Certificate info saved: {info_path}")

        cursor.close()
        return True

    def extract_caf_files(self, output_dir):
        """Extract CAF files for all DTE types"""
        print("\n📁 Extracting CAF Files...")

        cursor = self.conn.cursor()

        # Check if caf table exists
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'caf'
            )
        """)
        if not cursor.fetchone()[0]:
            print("⚠️  Table 'caf' not found - trying alternative names...")
            cursor.execute("""
                SELECT table_name FROM information_schema.tables
                WHERE table_name LIKE '%caf%'
            """)
            tables = cursor.fetchall()
            print(f"Found tables: {tables}")
            return False

        # Get CAF files with their DTE type
        cursor.execute("""
            SELECT
                c.id,
                c.name,
                c.caf_file,
                c.filename,
                c.start_nm,
                c.final_nm,
                c.use_level,
                c.state,
                sdc.sii_code
            FROM caf c
            LEFT JOIN sii_document_class sdc ON c.sii_document_class = sdc.id
            WHERE c.state IN ('in_use', 'draft')
            ORDER BY sdc.sii_code, c.final_nm DESC
        """)

        rows = cursor.fetchall()
        if not rows:
            print("❌ No CAF files found in database")
            return False

        print(f"✅ Found {len(rows)} CAF file(s)")

        caf_summary = []
        dte_types_found = set()

        for row in rows:
            caf_id, name, caf_file, filename, start, end, use_level, state, dte_code = row

            # Skip if already have this DTE type (keep most recent)
            if dte_code in dte_types_found:
                continue
            dte_types_found.add(dte_code)

            if not caf_file:
                print(f"⚠️  CAF ID {caf_id} has no file content, skipping")
                continue

            print(f"\n📄 CAF DTE {dte_code}:")
            print(f"   ID: {caf_id}")
            print(f"   Name: {name}")
            print(f"   Folios: {start} - {end}")
            print(f"   Use Level: {use_level:.1f}%" if use_level else "   Use Level: N/A")
            print(f"   State: {state}")

            # Save CAF file
            caf_filename = f"CAF_{dte_code}.xml" if dte_code else f"CAF_{caf_id}.xml"
            caf_path = os.path.join(output_dir, caf_filename)

            with open(caf_path, 'wb') as f:
                f.write(caf_file)
            print(f"   ✅ Saved: {caf_path}")

            caf_summary.append({
                'id': caf_id,
                'dte_code': dte_code,
                'name': name,
                'start': start,
                'end': end,
                'use_level': use_level,
                'state': state,
                'file': caf_filename
            })

        # Save CAF summary
        summary_path = os.path.join(output_dir, 'caf_summary.txt')
        with open(summary_path, 'w') as f:
            f.write(f"CAF Files Summary\n")
            f.write(f"{'=' * 80}\n")
            f.write(f"Extracted: {datetime.now().isoformat()}\n")
            f.write(f"Source DB: {self.db_name}\n")
            f.write(f"Total CAF files: {len(caf_summary)}\n\n")

            for caf in caf_summary:
                f.write(f"DTE Type {caf['dte_code']}:\n")
                f.write(f"  File: {caf['file']}\n")
                f.write(f"  Folios: {caf['start']} - {caf['end']} ({caf['end'] - caf['start'] + 1} total)\n")
                f.write(f"  Use Level: {caf['use_level']:.1f}%\n" if caf['use_level'] else "  Use Level: N/A\n")
                f.write(f"  State: {caf['state']}\n\n")

        print(f"\n✅ CAF summary saved: {summary_path}")

        cursor.close()
        return True

    def extract_company_config(self, output_dir):
        """Extract company SII configuration"""
        print("\n🏢 Extracting Company Configuration...")

        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT
                id,
                name,
                vat,
                street,
                city,
                phone,
                email
            FROM res_company
            WHERE id = 1
            LIMIT 1
        """)

        row = cursor.fetchone()
        if not row:
            print("⚠️  Company not found")
            return False

        company_id, name, vat, street, city, phone, email = row

        print(f"✅ Company found:")
        print(f"   Name: {name}")
        print(f"   RUT: {vat}")
        print(f"   Address: {street}, {city}")

        # Save company config
        config_path = os.path.join(output_dir, 'company_config.txt')
        with open(config_path, 'w') as f:
            f.write(f"Company Configuration\n")
            f.write(f"{'=' * 50}\n")
            f.write(f"Extracted: {datetime.now().isoformat()}\n")
            f.write(f"Source DB: {self.db_name}\n\n")
            f.write(f"ID: {company_id}\n")
            f.write(f"Name: {name}\n")
            f.write(f"RUT: {vat}\n")
            f.write(f"Address: {street}\n")
            f.write(f"City: {city}\n")
            f.write(f"Phone: {phone}\n")
            f.write(f"Email: {email}\n")

        print(f"✅ Company config saved: {config_path}")

        cursor.close()
        return True

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            print("\n🔌 Database connection closed")


def main():
    parser = argparse.ArgumentParser(
        description='Extract Certificate and CAF from Odoo 11 Database'
    )
    parser.add_argument('--db', required=True, help='Database name (e.g., odoo11_eergygroup)')
    parser.add_argument('--user', default='odoo', help='Database user (default: odoo)')
    parser.add_argument('--host', default='localhost', help='Database host (default: localhost)')
    parser.add_argument('--port', type=int, default=5432, help='Database port (default: 5432)')
    parser.add_argument('--password', help='Database password (will prompt if not provided)')
    parser.add_argument('--output', default='/tmp/export_odoo11', help='Output directory')

    args = parser.parse_args()

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"📁 Output directory: {output_dir}")

    # Prompt for password if not provided
    db_password = args.password
    if not db_password:
        import getpass
        db_password = getpass.getpass(f"Enter password for database user '{args.user}': ")

    # Extract data
    extractor = Odoo11Extractor(
        db_name=args.db,
        db_user=args.user,
        db_host=args.host,
        db_port=args.port,
        db_password=db_password
    )

    if not extractor.connect():
        sys.exit(1)

    try:
        cert_ok = extractor.extract_certificate(output_dir)
        caf_ok = extractor.extract_caf_files(output_dir)
        company_ok = extractor.extract_company_config(output_dir)

        print("\n" + "=" * 80)
        print("📊 EXTRACTION SUMMARY")
        print("=" * 80)
        print(f"Certificate: {'✅ Success' if cert_ok else '❌ Failed'}")
        print(f"CAF Files:   {'✅ Success' if caf_ok else '❌ Failed'}")
        print(f"Company:     {'✅ Success' if company_ok else '❌ Failed'}")
        print(f"\nOutput directory: {output_dir}")
        print("\n📋 NEXT STEPS:")
        print("1. Verify files integrity:")
        print(f"   ls -lh {output_dir}/")
        print("2. Validate certificate:")
        print(f"   openssl pkcs12 -info -in {output_dir}/certificado_produccion.p12 -noout")
        print("3. Import to Odoo 19 staging")
        print("=" * 80)

    finally:
        extractor.close()


if __name__ == '__main__':
    main()
