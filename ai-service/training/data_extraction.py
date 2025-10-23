"""
Data Extraction from Odoo PostgreSQL - 7 Years Historical Data
==============================================================

Extracts purchase invoices with analytic accounts for AI training.

Expected output: 100K-200K invoice lines with ground truth data.
"""

import os
import psycopg2
import pandas as pd
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OdooDataExtractor:
    """Extracts historical invoice data from Odoo PostgreSQL."""

    def __init__(self, db_config: Optional[Dict] = None):
        """
        Initialize extractor with database configuration.

        Args:
            db_config: PostgreSQL connection parameters
                       If None, reads from environment variables
        """
        self.db_config = db_config or {
            'host': os.getenv('ODOO_DB_HOST', 'localhost'),
            'port': os.getenv('ODOO_DB_PORT', '5432'),
            'database': os.getenv('ODOO_DB_NAME', 'odoo'),
            'user': os.getenv('ODOO_DB_USER', 'odoo'),
            'password': os.getenv('ODOO_DB_PASSWORD', 'odoo'),
        }
        self.conn = None

    def connect(self):
        """Establish database connection."""
        try:
            self.conn = psycopg2.connect(**self.db_config)
            logger.info(f"✅ Connected to database: {self.db_config['database']}")
        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            raise

    def disconnect(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")

    def extract_training_dataset(
        self,
        years: int = 7,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None
    ) -> pd.DataFrame:
        """
        Extract invoice lines with analytic accounts (GROUND TRUTH).

        This extracts:
        - Supplier invoices (in_invoice)
        - Posted state only (ground truth)
        - With analytic_distribution (this is what AI will learn to predict)
        - Product, account, supplier information
        - Linked purchase orders

        Args:
            years: Number of years to extract (default 7)
            start_date: Override start date (YYYY-MM-DD)
            end_date: Override end date (YYYY-MM-DD)

        Returns:
            DataFrame with columns:
                - line_id: account.move.line ID
                - invoice_id: account.move ID
                - invoice_date: Date of invoice
                - supplier_id: res.partner ID
                - supplier_name: Supplier name
                - supplier_rut: Chilean RUT
                - product_id: product.product ID
                - product_name: Product name
                - product_code: Default code
                - product_category: Category name
                - description: Line description
                - quantity: Quantity
                - price_unit: Unit price
                - price_subtotal: Subtotal
                - account_id: account.account ID (GROUND TRUTH)
                - account_code: Account code
                - account_name: Account name
                - analytic_distribution: JSON (GROUND TRUTH)
                - purchase_order_id: Linked PO ID
                - purchase_line_id: Linked PO line ID
        """
        if not self.conn:
            self.connect()

        # Calculate date range
        if not end_date:
            end_date = datetime.now().strftime('%Y-%m-%d')
        if not start_date:
            start_dt = datetime.now() - timedelta(days=years*365)
            start_date = start_dt.strftime('%Y-%m-%d')

        logger.info(f"📅 Extracting data from {start_date} to {end_date}")

        query = """
        SELECT
            aml.id AS line_id,
            am.id AS invoice_id,
            am.invoice_date,
            am.partner_id AS supplier_id,
            rp.name AS supplier_name,
            rp.vat AS supplier_rut,
            aml.product_id,
            COALESCE(pp.name_template, pt.name) AS product_name,
            pp.default_code AS product_code,
            pc.complete_name AS product_category,
            aml.name AS description,
            aml.quantity,
            aml.price_unit,
            aml.price_subtotal,
            aml.account_id,
            aa.code AS account_code,
            aa.name AS account_name,
            aml.analytic_distribution,
            am.purchase_id AS purchase_order_id,
            pol.id AS purchase_line_id
        FROM account_move_line aml

        -- Join invoice header
        JOIN account_move am ON am.id = aml.move_id

        -- Join supplier
        JOIN res_partner rp ON rp.id = am.partner_id

        -- Join account (LEFT because some lines might not have account)
        LEFT JOIN account_account aa ON aa.id = aml.account_id

        -- Join product (LEFT because some lines are text-only)
        LEFT JOIN product_product pp ON pp.id = aml.product_id
        LEFT JOIN product_template pt ON pt.id = pp.product_tmpl_id
        LEFT JOIN product_category pc ON pc.id = pt.categ_id

        -- Join purchase order line (LEFT because not all invoices have PO)
        LEFT JOIN purchase_order_line pol ON pol.id = aml.purchase_line_id

        WHERE
            am.move_type = 'in_invoice'          -- Supplier invoices only
            AND am.state = 'posted'               -- Only confirmed invoices (ground truth)
            AND am.invoice_date >= %(start_date)s
            AND am.invoice_date <= %(end_date)s
            AND aml.display_type IS NULL          -- Exclude section/note lines
            AND aml.exclude_from_invoice_tab = FALSE  -- Exclude tax lines

        ORDER BY am.invoice_date DESC, aml.id
        """

        try:
            logger.info("🔄 Executing query...")
            df = pd.read_sql_query(
                query,
                self.conn,
                params={'start_date': start_date, 'end_date': end_date}
            )

            logger.info(f"✅ Extracted {len(df):,} invoice lines")
            logger.info(f"   - Date range: {df['invoice_date'].min()} to {df['invoice_date'].max()}")
            logger.info(f"   - Unique invoices: {df['invoice_id'].nunique():,}")
            logger.info(f"   - Unique suppliers: {df['supplier_id'].nunique():,}")
            logger.info(f"   - Unique products: {df['product_id'].nunique():,}")
            logger.info(f"   - Lines with analytic: {df['analytic_distribution'].notna().sum():,}")
            logger.info(f"   - Lines with PO: {df['purchase_order_id'].notna().sum():,}")

            return df

        except Exception as e:
            logger.error(f"❌ Query failed: {e}")
            raise

    def extract_supplier_patterns(self) -> pd.DataFrame:
        """
        Extract supplier purchasing patterns for analysis.

        Returns:
            DataFrame with aggregated supplier data:
                - supplier_id
                - supplier_name
                - total_invoices
                - total_amount
                - avg_invoice_amount
                - most_common_products (top 10)
                - most_common_accounts (with counts)
                - most_common_analytics (with counts)
        """
        if not self.conn:
            self.connect()

        query = """
        SELECT
            rp.id AS supplier_id,
            rp.name AS supplier_name,
            COUNT(DISTINCT am.id) AS total_invoices,
            SUM(am.amount_total) AS total_amount,
            AVG(am.amount_total) AS avg_invoice_amount,
            COUNT(aml.id) AS total_lines,

            -- Most common products (as JSON array)
            json_agg(
                DISTINCT jsonb_build_object(
                    'product_id', aml.product_id,
                    'product_name', COALESCE(pp.name_template, pt.name)
                )
            ) FILTER (WHERE aml.product_id IS NOT NULL) AS products,

            -- Most common accounts
            json_agg(
                DISTINCT jsonb_build_object(
                    'account_id', aa.id,
                    'account_code', aa.code,
                    'account_name', aa.name
                )
            ) FILTER (WHERE aa.id IS NOT NULL) AS accounts

        FROM res_partner rp

        JOIN account_move am ON am.partner_id = rp.id
        JOIN account_move_line aml ON aml.move_id = am.id

        LEFT JOIN account_account aa ON aa.id = aml.account_id
        LEFT JOIN product_product pp ON pp.id = aml.product_id
        LEFT JOIN product_template pt ON pt.id = pp.product_tmpl_id

        WHERE
            am.move_type = 'in_invoice'
            AND am.state = 'posted'
            AND aml.display_type IS NULL
            AND aml.exclude_from_invoice_tab = FALSE

        GROUP BY rp.id, rp.name
        HAVING COUNT(DISTINCT am.id) >= 5  -- At least 5 invoices

        ORDER BY total_amount DESC
        """

        try:
            logger.info("🔄 Extracting supplier patterns...")
            df = pd.read_sql_query(query, self.conn)
            logger.info(f"✅ Extracted {len(df):,} supplier patterns")
            return df
        except Exception as e:
            logger.error(f"❌ Supplier pattern extraction failed: {e}")
            raise

    def save_to_csv(self, df: pd.DataFrame, filename: str):
        """Save DataFrame to CSV."""
        output_dir = "/app/training/data"
        os.makedirs(output_dir, exist_ok=True)

        filepath = os.path.join(output_dir, filename)
        df.to_csv(filepath, index=False, encoding='utf-8')

        logger.info(f"💾 Saved to: {filepath}")
        logger.info(f"   - File size: {os.path.getsize(filepath) / 1024 / 1024:.2f} MB")

        return filepath

    def get_statistics(self, df: pd.DataFrame) -> Dict:
        """Generate statistics for extracted data."""
        stats = {
            'total_lines': len(df),
            'date_range': {
                'start': str(df['invoice_date'].min()),
                'end': str(df['invoice_date'].max()),
                'days': (df['invoice_date'].max() - df['invoice_date'].min()).days
            },
            'invoices': {
                'total': df['invoice_id'].nunique(),
                'per_year': len(df) / (
                    (df['invoice_date'].max() - df['invoice_date'].min()).days / 365
                )
            },
            'suppliers': {
                'total': df['supplier_id'].nunique(),
                'with_rut': df['supplier_rut'].notna().sum(),
                'top_10': df.groupby('supplier_name')['invoice_id'].nunique().nlargest(10).to_dict()
            },
            'products': {
                'total': df['product_id'].nunique(),
                'with_code': df['product_code'].notna().sum(),
                'null_products': df['product_id'].isna().sum()
            },
            'accounts': {
                'total': df['account_id'].nunique(),
                'distribution': df.groupby('account_code')['line_id'].count().nlargest(20).to_dict()
            },
            'analytics': {
                'lines_with_analytics': df['analytic_distribution'].notna().sum(),
                'percentage': (df['analytic_distribution'].notna().sum() / len(df) * 100)
            },
            'purchase_orders': {
                'lines_with_po': df['purchase_order_id'].notna().sum(),
                'percentage': (df['purchase_order_id'].notna().sum() / len(df) * 100)
            }
        }

        return stats


def main():
    """Main execution function."""
    print("=" * 80)
    print("ODOO HISTORICAL DATA EXTRACTION")
    print("=" * 80)
    print()

    # Initialize extractor
    extractor = OdooDataExtractor()

    try:
        # Extract 7 years of data
        print("Step 1: Extracting invoice lines...")
        df_lines = extractor.extract_training_dataset(years=7)

        # Save to CSV
        print("\nStep 2: Saving to CSV...")
        filepath = extractor.save_to_csv(df_lines, 'historical_invoice_lines_7years.csv')

        # Extract supplier patterns
        print("\nStep 3: Extracting supplier patterns...")
        df_suppliers = extractor.extract_supplier_patterns()
        extractor.save_to_csv(df_suppliers, 'supplier_patterns.csv')

        # Generate statistics
        print("\nStep 4: Generating statistics...")
        stats = extractor.get_statistics(df_lines)

        # Save statistics
        stats_file = "/app/training/data/extraction_statistics.json"
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2, default=str)
        print(f"💾 Statistics saved to: {stats_file}")

        # Print summary
        print("\n" + "=" * 80)
        print("EXTRACTION SUMMARY")
        print("=" * 80)
        print(f"✅ Total invoice lines: {stats['total_lines']:,}")
        print(f"✅ Date range: {stats['date_range']['start']} to {stats['date_range']['end']}")
        print(f"✅ Total invoices: {stats['invoices']['total']:,}")
        print(f"✅ Unique suppliers: {stats['suppliers']['total']:,}")
        print(f"✅ Unique products: {stats['products']['total']:,}")
        print(f"✅ Lines with analytics: {stats['analytics']['lines_with_analytics']:,} ({stats['analytics']['percentage']:.1f}%)")
        print(f"✅ Lines with PO: {stats['purchase_orders']['lines_with_po']:,} ({stats['purchase_orders']['percentage']:.1f}%)")
        print()
        print("🎯 Next step: Run data_cleaning.py")
        print("=" * 80)

    finally:
        extractor.disconnect()


if __name__ == '__main__':
    main()
